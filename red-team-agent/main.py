"""Red team agent service — accepts HTTP requests to trigger agent runs."""
import os
import logging
import subprocess
import threading
import uuid

from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

REPO_URL      = os.environ.get('REPO_URL', 'https://github.com/wshxzt/grocerguard-arena.git')
WORKSPACE_DIR = os.environ.get('WORKSPACE_DIR', '/workspace/grocerguard-arena')
API_KEY       = os.environ.get('AGENT_API_KEY', '')

_runs: dict[str, dict] = {}
_runs_lock = threading.Lock()


def _check_auth():
    if not API_KEY:
        return None
    if request.headers.get('Authorization', '') != f'Bearer {API_KEY}':
        return jsonify({'error': 'unauthorized'}), 401
    return None


def setup_workspace():
    if os.path.isdir(os.path.join(WORKSPACE_DIR, '.git')):
        logger.info('Pulling latest codebase')
        result = subprocess.run(
            ['git', '-C', WORKSPACE_DIR, 'pull', '--ff-only'],
            capture_output=True, text=True,
        )
    else:
        logger.info(f'Cloning repo → {WORKSPACE_DIR}')
        os.makedirs(os.path.dirname(WORKSPACE_DIR), exist_ok=True)
        result = subprocess.run(
            ['git', 'clone', REPO_URL, WORKSPACE_DIR],
            capture_output=True, text=True,
        )
    if result.returncode != 0:
        raise RuntimeError(f'Git setup failed:\n{result.stderr}')


def _execute_run(run_id, cwe_id, cwe_name, cwe_score, mode, instructions):
    def update(status, detail=''):
        with _runs_lock:
            _runs[run_id]['status'] = status
            if detail:
                _runs[run_id]['detail'] = detail

    try:
        update('setting_up')
        setup_workspace()

        update('running', f'{cwe_id} / mode={mode}')

        # Import agent lazily so startup errors surface in request logs not at boot
        from agent import run_agent
        run_agent(cwe_id, cwe_name, cwe_score, mode=mode, instructions=instructions)
        update('done')
    except Exception as e:
        logger.exception(f'Run {run_id} failed')
        update('error', str(e))


@app.route('/')
def index():
    return jsonify({'service': 'red-team-agent', 'status': 'ok'})


@app.route('/run', methods=['POST'])
def trigger_run():
    err = _check_auth()
    if err:
        return err

    body         = request.get_json(silent=True) or {}
    instructions = body.get('instructions', '').strip()
    mode         = body.get('mode', 'both')
    cwe_override = body.get('cwe_id', '').strip()

    if mode not in ('inject', 'attack', 'both'):
        return jsonify({'error': 'mode must be inject | attack | both'}), 400

    import db
    import cwe_pipeline

    try:
        cwe_pipeline.sync_cwes()
    except Exception as e:
        logger.warning(f'CWE sync failed (non-fatal): {e}')

    if cwe_override:
        cwe = db.get_cwe(cwe_override)
        if not cwe:
            return jsonify({'error': f'CWE {cwe_override} not found in registry'}), 404
    else:
        cwe = db.get_next_cwe()
        if not cwe:
            return jsonify({'error': 'No applicable CWEs remaining'}), 409

    run_id = str(uuid.uuid4())
    with _runs_lock:
        _runs[run_id] = {
            'run_id':       run_id,
            'cwe_id':       cwe['cwe_id'],
            'cwe_name':     cwe['name'],
            'mode':         mode,
            'instructions': instructions,
            'status':       'queued',
            'detail':       '',
        }

    thread = threading.Thread(
        target=_execute_run,
        args=(run_id, cwe['cwe_id'], cwe['name'], cwe['score'], mode, instructions),
        daemon=True,
    )
    thread.start()

    logger.info(f'Run {run_id} started: {cwe["cwe_id"]} mode={mode}')
    return jsonify(_runs[run_id]), 202


@app.route('/runs', methods=['GET'])
def list_runs():
    err = _check_auth()
    if err:
        return err
    with _runs_lock:
        return jsonify(list(reversed(list(_runs.values()))))


@app.route('/runs/<run_id>', methods=['GET'])
def get_run(run_id):
    err = _check_auth()
    if err:
        return err
    with _runs_lock:
        run = _runs.get(run_id)
    if not run:
        return jsonify({'error': 'run not found'}), 404
    return jsonify(run)


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
