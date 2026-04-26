"""Blue team agent service — accepts HTTP requests and runs autonomous background scans."""
import os
import json
import logging
import threading
import time
import uuid

from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from google.adk.agents import Agent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://',
)

API_KEY       = os.environ.get('AGENT_API_KEY', '')
SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL_MINUTES', '10'))

_runs: dict[str, dict] = {}
_runs_lock = threading.Lock()
_run_reply_events: dict[str, threading.Event] = {}

# ── Chat System ────────────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are the GrocerGuard Blue Team assistant, running at the blue-team-agent service.
You help security engineers troubleshoot, defend, and patch the GrocerGuard application.

When the user asks to start/run/launch a scan, use trigger_scan.
When the user asks about status or results, use get_status.
For anything else, answer directly and help them troubleshoot.
"""

def trigger_scan(instructions: str = "") -> str:
    """Trigger a manual blue team defense scan. Pass instructions for the agent if requested."""
    run_id = str(uuid.uuid4())
    
    with _runs_lock:
        _runs[run_id] = {
            'run_id': run_id,
            'type': 'manual',
            'instructions': instructions,
            'status': 'queued',
            'detail': '',
            'steps': [],
            'pending_question': None,
            'started_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
        }
    threading.Thread(
        target=_execute_run,
        args=(run_id, instructions),
        daemon=True,
    ).start()
    return f'{{"run_id": "{run_id}", "status": "queued"}}'

def get_status(run_id: str = "") -> str:
    """Get status of recent blue team runs. Optionally provide a run_id to get specific status."""
    with _runs_lock:
        if run_id:
            return json.dumps(_runs.get(run_id, {'error': 'run not found'}))
        return json.dumps(list(reversed(list(_runs.values())))[-10:])


chat_agent = Agent(
    name="chat_assistant",
    model="gemini-3.1-flash",
    instruction=_CHAT_SYSTEM,
    tools=[trigger_scan, get_status]
)

# ── Background Execution & Autonomous Scanner ──────────────────────────────────

def _execute_run(run_id, instructions=''):
    def update(status, detail=''):
        with _runs_lock:
            _runs[run_id]['status'] = status
            if detail:
                _runs[run_id]['detail'] = detail

    def on_progress(steps):
        with _runs_lock:
            _runs[run_id]['steps'] = (_runs[run_id].get('steps', []) + steps)[-40:]

    reply_event = threading.Event()
    with _runs_lock:
        _run_reply_events[run_id] = reply_event

    def on_ask_user(question):
        reply_event.clear()
        with _runs_lock:
            _runs[run_id]['pending_question'] = question
            _runs[run_id]['status'] = 'waiting'
        logger.info(f'Run {run_id} waiting for user input: {question[:80]}')
        reply_event.wait()
        with _runs_lock:
            reply = _runs[run_id].pop('pending_reply', '')
            _runs[run_id]['pending_question'] = None
            _runs[run_id]['status'] = 'running'
        logger.info(f'Run {run_id} got user reply: {reply[:80]}')
        return reply

    try:
        update('running')
        from agent import run_agent
        run_agent(instructions=instructions, on_progress=on_progress, on_ask_user=on_ask_user)
        update('done')
    except Exception as e:
        logger.exception(f'Run {run_id} failed')
        update('error', str(e))
    finally:
        _run_reply_events.pop(run_id, None)


def _autonomous_scanner_loop():
    """Run a scan every SCAN_INTERVAL minutes."""
    while True:
        time.sleep(SCAN_INTERVAL * 60)
        logger.info('Starting autonomous blue team scan.')
        run_id = str(uuid.uuid4())
        with _runs_lock:
            _runs[run_id] = {
                'run_id': run_id,
                'type': 'autonomous',
                'instructions': 'Autonomous background scan.',
                'status': 'queued',
                'detail': '',
                'steps': [],
                'pending_question': None,
                'started_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
            }
        _execute_run(run_id, instructions='Autonomous background scan.')

threading.Thread(target=_autonomous_scanner_loop, daemon=True).start()

# ── Auth Helper ───────────────────────────────────────────────────────────────

def _check_auth():
    if not API_KEY:
        return None
    if request.headers.get('Authorization', '') != f'Bearer {API_KEY}':
        return jsonify({'error': 'unauthorized'}), 401
    return None

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/chat', methods=['POST'])
@limiter.limit('12 per minute')
def chat():
    data     = request.get_json(silent=True) or {}
    user_msg = data.get('message', '').strip()
    history  = data.get('history', [])

    if not user_msg:
        return jsonify({'error': 'empty message'}), 400

    try:
        # NOTE: If we want to support conversational history with ADK, 
        # we can pass it if supported by `agent.run()`, 
        # but for simplicity we will just append it as context if history is available.
        context = ""
        if history:
            context = "Previous Conversation:\\n"
            for m in history:
                if isinstance(m, dict) and "content" in m and isinstance(m["content"], str):
                    role = "user" if m.get("role") == "user" else "assistant"
                    context += f"{role.capitalize()}: {m['content']}\\n"
            context += "\\nUser's new message:\\n"
        
        prompt = context + user_msg

        # Adk handles tool loop internally
        response = chat_agent.run(prompt)

        # Build clean history for frontend
        frontend_history = []
        for m in history:
             if isinstance(m, dict) and "content" in m and isinstance(m["content"], str):
                 r = "user" if m.get("role") == "user" else "assistant"
                 frontend_history.append({"role": r, "content": m["content"]})
        
        # We don't have direct access to internal tool calls from the simple .run() API 
        # to extract started_run_id reliably without parsing, but the frontend will just poll if needed.

        return jsonify({
            'reply': str(response) or "(no response)",
            'history': frontend_history,
            'started_run_id': None,
        })
    except Exception as e:
        logger.exception("Chat failed")
        return jsonify({'error': str(e)}), 500


@app.route('/run', methods=['POST'])
def trigger_run():
    err = _check_auth()
    if err: return err

    body         = request.get_json(silent=True) or {}
    instructions = body.get('instructions', '').strip()

    run_id = str(uuid.uuid4())
    with _runs_lock:
        _runs[run_id] = {
            'run_id': run_id,
            'type': 'manual',
            'instructions': instructions,
            'status': 'queued',
            'detail': '',
            'steps': [],
            'pending_question': None,
            'started_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
        }
    threading.Thread(
        target=_execute_run,
        args=(run_id, instructions),
        daemon=True,
    ).start()

    logger.info(f'Run {run_id} started (manual)')
    return jsonify(_runs[run_id]), 202


@app.route('/runs', methods=['GET'])
def list_runs():
    err = _check_auth()
    if err: return err
    with _runs_lock:
        return jsonify(list(reversed(list(_runs.values()))))


@app.route('/runs/<run_id>', methods=['GET'])
def get_run(run_id):
    err = _check_auth()
    if err: return err
    with _runs_lock:
        run = _runs.get(run_id)
    if not run:
        return jsonify({'error': 'run not found'}), 404
    return jsonify({k: v for k, v in run.items() if not k.startswith('_')})


@app.route('/runs/<run_id>/reply', methods=['POST'])
def reply_run(run_id):
    body = request.get_json(silent=True) or {}
    reply = body.get('reply', '').strip()
    with _runs_lock:
        run = _runs.get(run_id)
        if not run:
            return jsonify({'error': 'run not found'}), 404
        if not run.get('pending_question'):
            return jsonify({'error': 'run is not waiting for input'}), 400
        run['pending_reply'] = reply
    event = _run_reply_events.get(run_id)
    if event:
        event.set()
    return jsonify({'ok': True})


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8081)))
