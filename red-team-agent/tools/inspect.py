"""Pull the live grocerguard container and sync its app/ contents into the
red team's CODEBASE_DIR before each run. Without this, every red deploy
clobbers blue team's runtime patches because red builds from its own git
checkout, not the actual deployed source.

Mirrors blue-team-agent/tools/skills.py inspect_deployed_filesystem; kept
here as its own module so it doesn't pull in unrelated blue team scan logic."""
import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

CODEBASE_DIR = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')

# Files in CODEBASE_DIR that we ALWAYS keep (the deployed image doesn't
# contain a Dockerfile, but the build needs one).
_PRESERVE = {'Dockerfile', '.dockerignore', '.gcloudignore'}


def inspect_and_sync_deployed(service_name: str = 'grocerguard') -> str:
    """Pull the live image for `service_name` and overwrite CODEBASE_DIR's
    app source with what's deployed. Returns a status string."""
    out_dir = f'/tmp/inspections/{service_name}'

    # 1) Resolve the deployed image URL for the live Cloud Run service.
    try:
        res = subprocess.run(
            ['gcloud', 'run', 'services', 'describe', service_name,
             '--region', 'us-central1',
             '--format=value(spec.template.spec.containers[0].image)'],
            capture_output=True, text=True, check=True, timeout=30,
        )
        image_url = res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f'inspect_and_sync: gcloud describe failed: {e.stderr[:200]}'
    if not image_url:
        return 'inspect_and_sync: could not resolve deployed image URL'

    logger.info(f'inspect_and_sync: pulling {image_url}')

    # 2) Wipe and recreate the inspection out_dir.
    os.makedirs(out_dir, exist_ok=True)
    for entry in os.listdir(out_dir):
        target = os.path.join(out_dir, entry)
        try:
            shutil.rmtree(target) if os.path.isdir(target) else os.unlink(target)
        except Exception:
            pass

    # 3) Configure docker credential helper so crane can authenticate to GCR/AR.
    subprocess.run(
        ['gcloud', 'auth', 'configure-docker',
         'gcr.io,us-central1-docker.pkg.dev', '--quiet'],
        capture_output=True,
    )

    # 4) crane export | tar -x. Capture both stderr streams.
    crane_proc = subprocess.Popen(
        ['crane', 'export', image_url, '-'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    tar_result = subprocess.run(
        ['tar', '-xf', '-', '-C', out_dir],
        stdin=crane_proc.stdout, capture_output=True,
    )
    crane_proc.stdout.close()
    crane_rc = crane_proc.wait()
    crane_stderr = crane_proc.stderr.read().decode()

    if crane_rc != 0:
        logger.warning(f'inspect_and_sync: crane failed (rc={crane_rc}): {crane_stderr[:300]}')
        return f'inspect_and_sync: crane failed: {crane_stderr}'
    if tar_result.returncode != 0:
        return f'inspect_and_sync: tar failed: {tar_result.stderr.decode()}'

    extracted_app = os.path.join(out_dir, 'app')
    if not os.path.isdir(extracted_app):
        return f'inspect_and_sync: no app/ in extracted image at {out_dir}'

    # 5) Wipe CODEBASE_DIR (except preserved files) and copy in the deployed
    #    app source so the next deploy builds on top of what's actually live.
    os.makedirs(CODEBASE_DIR, exist_ok=True)
    try:
        for entry in os.listdir(CODEBASE_DIR):
            if entry in _PRESERVE:
                continue
            target = os.path.join(CODEBASE_DIR, entry)
            if os.path.isdir(target):
                shutil.rmtree(target)
            else:
                os.unlink(target)
        for entry in os.listdir(extracted_app):
            src = os.path.join(extracted_app, entry)
            dst = os.path.join(CODEBASE_DIR, entry)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            else:
                shutil.copy2(src, dst)
    except Exception as e:
        logger.warning(f'inspect_and_sync: sync to CODEBASE_DIR failed: {e}')
        return f'inspect_and_sync: sync failed: {e}'

    logger.info(f'inspect_and_sync: synced {extracted_app}/ → {CODEBASE_DIR}/')
    return f'inspect_and_sync: synced deployed {image_url} into {CODEBASE_DIR}'
