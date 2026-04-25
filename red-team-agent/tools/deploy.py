"""Build and deploy the vulnerable GrocerGuard codebase to grocerguard-redteam."""
import os
import time
import logging
import subprocess
import requests

logger = logging.getLogger(__name__)

PROJECT      = os.environ['SPANNER_PROJECT_ID']
REGION       = os.environ.get('REGION', 'us-central1')
SERVICE      = 'grocerguard-redteam'
IMAGE        = f'gcr.io/{PROJECT}/{SERVICE}:latest'
CODEBASE_DIR = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')


def _run(cmd, timeout=300):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired as e:
        # Process is already killed by subprocess.run before re-raising.
        # The GCP-side operation (build/deploy) may still be running.
        out = e.stdout.decode(errors='replace').strip() if isinstance(e.stdout, bytes) else ''
        return None, out, f'local command timed out after {timeout}s'


def _get_service_url():
    # Prefer the env var (already configured to point at grocerguard-redteam)
    # to avoid needing Cloud Run describe permissions.
    env_url = os.environ.get('APP_BASE_URL', '').strip()
    if env_url:
        return env_url
    _, url, _ = _run([
        'gcloud', 'run', 'services', 'describe', SERVICE,
        '--region', REGION, '--project', PROJECT,
        '--format', 'value(status.url)',
    ], timeout=30)
    return url.strip()


def _wait_healthy(url, retries=18, interval=10):
    for i in range(retries):
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        logger.info(f'Health check {i+1}/{retries}: not ready yet')
        time.sleep(interval)
    return False


def deploy():
    logger.info(f'Submitting Cloud Build from {CODEBASE_DIR}')
    code, out, err = _run(
        ['gcloud', 'builds', 'submit', '--tag', IMAGE, '--project', PROJECT, CODEBASE_DIR],
        timeout=480,
    )
    if code != 0:
        # None means timed out — build may be running; treat as hard failure since we can't deploy without the image
        return f'Build failed (code={code}):\n{err}'
    logger.info('Build succeeded. Deploying...')

    env_vars = (
        f'SPANNER_PROJECT_ID={os.environ["SPANNER_PROJECT_ID"]},'
        f'SPANNER_INSTANCE_ID={os.environ["SPANNER_INSTANCE_ID"]},'
        f'SPANNER_DATABASE_ID={os.environ.get("SPANNER_DATABASE_ID", "grocerguard")},'
        f'GCS_BUCKET_NAME={os.environ.get("GCS_BUCKET_NAME", "")},'
        f'APP_BASE_URL={os.environ.get("APP_BASE_URL", "")}'
    )

    code, out, err = _run([
        'gcloud', 'run', 'deploy', SERVICE,
        '--image', IMAGE,
        '--region', REGION,
        '--platform', 'managed',
        '--allow-unauthenticated',
        '--set-env-vars', env_vars,
        '--set-secrets', 'SECRET_KEY=grocerguard-secret-key:latest',
        '--project', PROJECT,
    ], timeout=360)

    if code is not None and code != 0:
        return f'Deploy failed:\n{err}'

    if code is None:
        # The local gcloud process was killed after 360s, but Cloud Run may have
        # accepted the revision and is still rolling it out. Fall through and
        # check health directly rather than aborting.
        logger.warning('gcloud run deploy timed out locally — checking if service came up anyway')

    url = _get_service_url()
    if not url:
        return 'Deploy submitted but could not determine service URL'

    logger.info(f'Polling {url}/healthz ...')
    if _wait_healthy(url):
        logger.info('Service is live.')
        return f'Deployed. Service URL: {url}'

    return f'Deploy submitted but health check timed out. Service URL: {url}'
