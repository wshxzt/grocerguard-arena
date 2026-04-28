import os
import subprocess
import shutil
import glob
import re
import logging

logger = logging.getLogger(__name__)

def fetch_service_logs(service_name: str, limit: int = 50) -> str:
    """Fetch recent application logs from a Cloud Run service using gcloud."""
    logger.info(f'fetch_service_logs: service={service_name} limit={limit}')
    try:
        cmd = ["gcloud", "run", "services", "logs", "read", service_name, "--region", "us-central1", "--limit", str(limit)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout if result.stdout else "No logs found or empty response."
        logger.info(f'fetch_service_logs: got {len(output.splitlines())} lines from {service_name}')
        return output
    except subprocess.CalledProcessError as e:
        logger.warning(f'fetch_service_logs failed: {e.stderr[:200]}')
        return f"Error fetching logs: {e.stderr}"
    except Exception as e:
        logger.warning(f'fetch_service_logs error: {e}')
        return f"Error: {e}"

def search_service_logs(service_name: str, query: str, limit: int = 30) -> str:
    """Search Cloud Run service logs for a substring match.

    Use for CWE-specific forensics, e.g.:
      search_service_logs("grocerguard", "UNION SELECT")  # SQLi
      search_service_logs("grocerguard", "<script")        # XSS
      search_service_logs("grocerguard", "; rm ")          # command injection
      search_service_logs("grocerguard", "../")            # path traversal
      search_service_logs("grocerguard", "%27")            # URL-encoded quote (SQLi)
    """
    logger.info(f'search_service_logs: service={service_name} query={query!r} limit={limit}')
    project = os.environ.get('SPANNER_PROJECT_ID', 'zhiting-personal')
    # Search BOTH stdout/stderr (textPayload) AND HTTP request URLs
    # (httpRequest.requestUrl) — attack payloads usually live in the URL.
    filter_str = (
        f'resource.type="cloud_run_revision" '
        f'AND resource.labels.service_name="{service_name}" '
        f'AND (textPayload:"{query}" OR httpRequest.requestUrl:"{query}")'
    )
    try:
        result = subprocess.run(
            ['gcloud', 'logging', 'read', filter_str,
             '--limit', str(limit),
             '--format', 'value(timestamp,httpRequest.requestUrl,textPayload)',
             '--order', 'desc',
             '--project', project],
            capture_output=True, text=True, check=True, timeout=30,
        )
        output = result.stdout.strip() if result.stdout else "(no matching log entries)"
        logger.info(f'search_service_logs: got {len(output.splitlines())} lines for {query!r}')
        return output
    except subprocess.CalledProcessError as e:
        logger.warning(f'search_service_logs failed: {e.stderr[:200]}')
        return f"Error searching logs: {e.stderr}"
    except Exception as e:
        logger.warning(f'search_service_logs error: {e}')
        return f"Error: {e}"


def inspect_deployed_filesystem(service_name: str) -> str:
    """Finds the currently deployed image for a service and uses crane to extract its filesystem to /tmp/inspections/<service_name>."""
    logger.info(f'inspect_deployed_filesystem: service={service_name}')
    try:
        cmd_img = [
            "gcloud", "run", "services", "describe", service_name,
            "--region", "us-central1",
            "--format=value(spec.template.spec.containers[0].image)"
        ]
        res_img = subprocess.run(cmd_img, capture_output=True, text=True, check=True)
        image_url = res_img.stdout.strip()

        if not image_url:
            logger.warning('inspect_deployed_filesystem: could not determine image URL')
            return "Could not determine deployed image URL."

        logger.info(f'inspect_deployed_filesystem: pulling image {image_url}')
        out_dir = f"/tmp/inspections/{service_name}"
        os.makedirs(out_dir, exist_ok=True)

        for filename in os.listdir(out_dir):
            file_path = os.path.join(out_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception:
                pass

        # Configure docker credential helper so crane can authenticate with GCR/AR.
        subprocess.run(
            ['gcloud', 'auth', 'configure-docker', 'gcr.io,us-central1-docker.pkg.dev', '--quiet'],
            capture_output=True,
        )

        crane_cmd = ["crane", "export", image_url, "-"]
        tar_cmd = ["tar", "-xf", "-", "-C", out_dir]

        crane_process = subprocess.Popen(crane_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tar_result = subprocess.run(tar_cmd, stdin=crane_process.stdout, capture_output=True)
        crane_process.stdout.close()
        crane_returncode = crane_process.wait()
        crane_stderr = crane_process.stderr.read().decode()

        if crane_returncode != 0:
            logger.warning(f'inspect_deployed_filesystem: crane failed (rc={crane_returncode}): {crane_stderr[:300]}')
            return f"Error: crane failed to pull {image_url}: {crane_stderr}"

        if tar_result.returncode != 0:
            tar_stderr = tar_result.stderr.decode()
            logger.warning(f'inspect_deployed_filesystem: tar failed: {tar_stderr[:200]}')
            return f"Error: tar extraction failed: {tar_stderr}"

        logger.info(f'inspect_deployed_filesystem: extracted to {out_dir}')

        # Sync the deployed app source into CODEBASE_DIR so the patch phase
        # can read/write files the red team added that aren't in our bundle.
        extracted_app = os.path.join(out_dir, 'app')
        codebase_dir = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')
        synced_msg = ''
        if os.path.isdir(extracted_app) and codebase_dir:
            try:
                _PRESERVE = {'Dockerfile', '.dockerignore', '.gcloudignore'}
                os.makedirs(codebase_dir, exist_ok=True)
                # Wipe everything in CODEBASE_DIR except files we always want to keep.
                for entry in os.listdir(codebase_dir):
                    if entry in _PRESERVE:
                        continue
                    target = os.path.join(codebase_dir, entry)
                    if os.path.isdir(target):
                        shutil.rmtree(target)
                    else:
                        os.unlink(target)
                # Copy deployed app contents in.
                for entry in os.listdir(extracted_app):
                    src = os.path.join(extracted_app, entry)
                    dst = os.path.join(codebase_dir, entry)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                    else:
                        shutil.copy2(src, dst)
                logger.info(f'inspect_deployed_filesystem: synced {extracted_app}/ → {codebase_dir}/')
                synced_msg = f' Synced deployed source into {codebase_dir} (patch phase will read/write here).'
            except Exception as e:
                logger.warning(f'inspect_deployed_filesystem: sync to CODEBASE_DIR failed: {e}')
                synced_msg = f' WARNING: failed to sync deployed source into CODEBASE_DIR: {e}'

        return f"Successfully extracted deployed filesystem of {image_url} to {out_dir}.{synced_msg} You can now use list_files and read_file on either path."
    except Exception as e:
        logger.warning(f'inspect_deployed_filesystem: error: {e}')
        return f"Error: {e}"

def scan_top_cwes(directory: str) -> str:
    """Run localized heuristic scans on the codebase for Top CWEs (SQLi, XSS, OS Command Injection)."""
    logger.info(f'scan_top_cwes: directory={directory}')
    if not directory:
        directory = "."

    results = []

    # 1. CWE-89: SQL Injection — covers many shapes (Spanner execute_sql, SQLAlchemy
    # text(), raw .execute(), and f-strings/concat/format/% containing SQL keywords).
    sqli_patterns = [
        # .execute / .execute_sql / .execute_update with unsafe formatting
        re.compile(r'\.execute(_sql|_update)?\s*\(\s*f["\']'),
        re.compile(r'\.execute(_sql|_update)?\s*\([^)]*\.format\s*\('),
        re.compile(r'\.execute(_sql|_update)?\s*\([^)]*%\s*[\(\w]'),
        re.compile(r'\.execute(_sql|_update)?\s*\([^)]*\+\s*\w'),
        # SQLAlchemy text() with unsafe formatting
        re.compile(r'\btext\s*\(\s*f["\']'),
        re.compile(r'\btext\s*\([^)]*\.format\s*\('),
        re.compile(r'\btext\s*\([^)]*\+\s*\w'),
        re.compile(r'\btext\s*\([^)]*%\s*[\(\w]'),
        # f-string or concat/format directly assembling a SQL keyword string
        re.compile(r'f["\'][^"\']*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b', re.IGNORECASE),
        re.compile(r'["\'][^"\']*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"\']*["\']\s*[%+]', re.IGNORECASE),
        re.compile(r'["\'][^"\']*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"\']*["\']\s*\.\s*format\s*\(', re.IGNORECASE),
    ]

    # 2. CWE-79: XSS — Jinja `|safe`, autoescape off, or Markup() with user input.
    xss_patterns = [
        re.compile(r'\{\{[^}]*\|\s*safe\s*\}\}'),
        re.compile(r'\{%\s*autoescape\s+false\s*%\}', re.IGNORECASE),
        re.compile(r'\bMarkup\s*\([^)]*[\+%f]'),
    ]

    # 3. CWE-78: OS Command Injection — os.system, shell=True, popen.
    cmd_inj_patterns = [
        re.compile(r'os\.system\s*\('),
        re.compile(r'subprocess\.(Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True'),
        re.compile(r'os\.popen\s*\('),
    ]

    for root, _, files in os.walk(directory):
        if '/venv' in root or '/.git' in root or '__pycache__' in root:
            continue
        for file in files:
            if not file.endswith(('.py', '.html')):
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                if file.endswith('.py'):
                    for i, line in enumerate(content.splitlines()):
                        if any(p.search(line) for p in sqli_patterns):
                            results.append(f"Potential CWE-89 (SQLi) at {filepath}:{i+1} -> {line.strip()[:200]}")
                        if any(p.search(line) for p in cmd_inj_patterns):
                            results.append(f"Potential CWE-78 (OS Cmd Inj) at {filepath}:{i+1} -> {line.strip()[:200]}")

                elif file.endswith('.html'):
                    for i, line in enumerate(content.splitlines()):
                        if any(p.search(line) for p in xss_patterns):
                            results.append(f"Potential CWE-79 (XSS) at {filepath}:{i+1} -> {line.strip()[:200]}")
            except Exception:
                pass

    if not results:
        logger.info('scan_top_cwes: no findings')
        return "No obvious Top CWEs found via heuristic scan."
    logger.info(f'scan_top_cwes: {len(results)} finding(s)')
    for r in results:
        logger.info(f'  CWE finding: {r}')
    return "Heuristic Scan Results:\n" + "\n".join(results)
