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
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def deploy():
    logger.info(f'Submitting Cloud Build from {CODEBASE_DIR}')
    code, out, err = _run(
        ['gcloud', 'builds', 'submit', '--tag', IMAGE,
         '--project', PROJECT, CODEBASE_DIR],
        timeout=360
    )
    if code != 0:
        return f'Build failed:\n{err}'
    logger.info('Build succeeded. Deploying...')

    spanner_project  = os.environ['SPANNER_PROJECT_ID']
    spanner_instance = os.environ['SPANNER_INSTANCE_ID']
    spanner_db       = os.environ.get('SPANNER_DATABASE_ID', 'grocerguard')
    gcs_bucket       = os.environ.get('GCS_BUCKET_NAME', '')
    base_url         = os.environ.get('REDTEAM_BASE_URL', '')

    code, out, err = _run([
        'gcloud', 'run', 'deploy', SERVICE,
        '--image', IMAGE,
        '--region', REGION,
        '--platform', 'managed',
        '--allow-unauthenticated',
        '--set-env-vars',
        (f'SPANNER_PROJECT_ID={spanner_project},'
         f'SPANNER_INSTANCE_ID={spanner_instance},'
         f'SPANNER_DATABASE_ID={spanner_db},'
         f'GCS_BUCKET_NAME={gcs_bucket},'
         f'APP_BASE_URL={base_url}'),
        '--set-secrets', 'SECRET_KEY=grocerguard-secret-key:latest',
        '--project', PROJECT,
    ], timeout=180)
    if code != 0:
        return f'Deploy failed:\n{err}'

    # Get service URL
    _, url, _ = _run([
        'gcloud', 'run', 'services', 'describe', SERVICE,
        '--region', REGION, '--project', PROJECT,
        '--format', 'value(status.url)',
    ])

    # Poll until healthy
    logger.info(f'Waiting for {url}/healthz ...')
    for _ in range(24):
        try:
            if requests.get(f'{url}/healthz', timeout=5).status_code == 200:
                logger.info('Service is live.')
                return f'Deployed. Service URL: {url}'
        except Exception:
            pass
        time.sleep(10)

    return f'Deployed but health check timed out. Service URL: {url}'
