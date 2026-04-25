"""Entry point for the GrocerGuard red team agent Cloud Run Job."""
import os
import logging
import subprocess

import db
import cwe_pipeline
from agent import run_agent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

REPO_URL      = os.environ.get('REPO_URL', 'https://github.com/wshxzt/grocerguard-arena.git')
WORKSPACE_DIR = os.environ.get('WORKSPACE_DIR', '/workspace/grocerguard-arena')
CODEBASE_DIR  = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')


def setup_workspace():
    """Clone or update the GrocerGuard codebase into the workspace."""
    if os.path.isdir(os.path.join(WORKSPACE_DIR, '.git')):
        logger.info('Workspace exists — pulling latest changes')
        result = subprocess.run(
            ['git', '-C', WORKSPACE_DIR, 'pull', '--ff-only'],
            capture_output=True, text=True,
        )
    else:
        logger.info(f'Cloning {REPO_URL} → {WORKSPACE_DIR}')
        os.makedirs(os.path.dirname(WORKSPACE_DIR), exist_ok=True)
        result = subprocess.run(
            ['git', 'clone', REPO_URL, WORKSPACE_DIR],
            capture_output=True, text=True,
        )

    if result.returncode != 0:
        raise RuntimeError(f'Git workspace setup failed:\n{result.stderr}')

    logger.info(f'Workspace ready at {WORKSPACE_DIR}')


def main():
    logger.info('=== GrocerGuard Red Team Agent starting ===')

    # 1. Prepare the codebase
    setup_workspace()

    # 2. Sync latest CWEs from MITRE
    synced = cwe_pipeline.sync_cwes()
    logger.info(f'CWE sync complete: {synced} entries')

    # 3. Pick the next CWE to exploit
    cwe = db.get_next_cwe()
    if not cwe:
        logger.info('No applicable CWEs remaining — nothing to do this run.')
        return

    cwe_id, cwe_name, cwe_score = cwe['cwe_id'], cwe['name'], cwe['score']
    logger.info(f'Selected {cwe_id}: {cwe_name} (score={cwe_score})')

    # 4. Run the Claude agent (with optional instructions from env)
    instructions = os.environ.get('AGENT_INSTRUCTIONS', '').strip()
    if instructions:
        logger.info(f'Agent instructions: {instructions}')
    run_agent(cwe_id, cwe_name, cwe_score, instructions=instructions)

    logger.info('=== Red Team Agent run complete ===')


if __name__ == '__main__':
    main()
