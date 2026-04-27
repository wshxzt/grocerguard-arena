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
        return f"Successfully extracted deployed filesystem of {image_url} to {out_dir}. You can now use your list_files and read_file tools on this directory."
    except Exception as e:
        logger.warning(f'inspect_deployed_filesystem: error: {e}')
        return f"Error: {e}"

def scan_top_cwes(directory: str) -> str:
    """Run localized heuristic scans on the codebase for Top CWEs (SQLi, XSS, OS Command Injection)."""
    logger.info(f'scan_top_cwes: directory={directory}')
    if not directory:
        directory = "."

    results = []

    # 1. CWE-89: SQL Injection (naive check for string formatting in execute calls)
    sqli_pattern = re.compile(
        r'\.execute\s*\(\s*f["\'].*\{'
        r'|\.execute\s*\(\s*["\'].*%'
        r'|\.execute\s*\(\s*.*\.format\('
    )

    # 2. CWE-79: XSS (naive check for |safe in Jinja templates)
    xss_pattern = re.compile(r'\{\{.*\|safe\s*\}\}')

    # 3. CWE-78: OS Command Injection (naive check for shell=True or os.system)
    cmd_inj_pattern = re.compile(
        r'os\.system\s*\(|subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True'
    )

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
                        if sqli_pattern.search(line):
                            results.append(f"Potential CWE-89 (SQLi) at {filepath}:{i+1} -> {line.strip()}")
                        if cmd_inj_pattern.search(line):
                            results.append(f"Potential CWE-78 (OS Cmd Inj) at {filepath}:{i+1} -> {line.strip()}")

                elif file.endswith('.html'):
                    for i, line in enumerate(content.splitlines()):
                        if xss_pattern.search(line):
                            results.append(f"Potential CWE-79 (XSS) at {filepath}:{i+1} -> {line.strip()}")
            except Exception:
                pass

    if not results:
        logger.info('scan_top_cwes: no findings')
        return "No obvious Top CWEs found via heuristic scan."
    logger.info(f'scan_top_cwes: {len(results)} finding(s)')
    for r in results:
        logger.info(f'  CWE finding: {r}')
    return "Heuristic Scan Results:\n" + "\n".join(results)
