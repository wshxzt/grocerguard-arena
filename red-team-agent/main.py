"""Red team agent service — accepts HTTP requests to trigger agent runs."""
import os
import json
import logging
import random
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

_PST = ZoneInfo('America/Los_Angeles')

import anthropic
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # no blanket limit; apply per-route
    storage_uri='memory://',
)

_anthropic = anthropic.Anthropic()

REPO_URL      = os.environ.get('REPO_URL', 'https://github.com/wshxzt/grocerguard-arena.git')
WORKSPACE_DIR = os.environ.get('WORKSPACE_DIR', '/workspace/grocerguard-arena')
API_KEY       = os.environ.get('AGENT_API_KEY', '')
SELF_URL      = os.environ.get('SELF_URL', '')

_runs: dict[str, dict] = {}
_runs_lock = threading.Lock()
_run_reply_events: dict[str, threading.Event] = {}
_run_stop_events: dict[str, threading.Event] = {}


_ACTIVE_STATES = ('queued', 'setting_up', 'running', 'waiting')


def _stop_run(run_id: str = '') -> dict:
    """Signal run(s) to stop.
    - If run_id is given: stop that run.
    - If run_id is empty: stop ALL currently active runs.
    """
    with _runs_lock:
        if run_id:
            target_ids = [run_id] if run_id in _runs else []
        else:
            target_ids = [rid for rid, run in _runs.items()
                          if run.get('status') in _ACTIVE_STATES]
    if not target_ids:
        return {'error': 'no active run to stop' if not run_id else f'run {run_id} not found'}

    stopped, skipped = [], []
    for rid in target_ids:
        ev = _run_stop_events.get(rid)
        if ev is None:
            skipped.append(rid)
            continue
        ev.set()
        # Unblock any pending ask_user wait so the agent can exit cleanly.
        reply_ev = _run_reply_events.get(rid)
        if reply_ev is not None:
            with _runs_lock:
                _runs[rid]['pending_reply'] = ''
                _runs[rid]['pending_question'] = None
            reply_ev.set()
        stopped.append(rid)
        logger.info(f'Run {rid} stop requested')

    return {
        'stopped': stopped,
        'skipped': skipped,
        'note': 'stop will take effect after each in-flight Claude turn finishes (≤60s).',
    }


def _keepalive_loop():
    """Ping our own /healthz every 45s while any run is active, so Cloud Run
    doesn't kill the instance mid-run (it only counts load-balancer traffic)."""
    import requests as _req
    _ACTIVE = {'queued', 'setting_up', 'running', 'waiting'}
    while True:
        time.sleep(45)
        if not SELF_URL:
            continue
        with _runs_lock:
            has_active = any(r.get('status') in _ACTIVE for r in _runs.values())
        if has_active:
            try:
                _req.get(f'{SELF_URL}/healthz', timeout=5)
            except Exception:
                pass


threading.Thread(target=_keepalive_loop, daemon=True).start()

# ── Claude chat ────────────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are the GrocerGuard Red Team assistant, running at the red-team-agent service.
You help users manage automated security attacks against the GrocerGuard target application.

You have four tools:
- start_attack: trigger a red team run (inject a vulnerability, attack it, or both)
- stop_attack: stop a currently running attack (use when the user asks to stop / cancel / kill / abort)
- get_status: check the status of recent runs
- list_cwes: read the CWE registry — returns CWEs with rank/score and whether they've been attacked yet. USE THIS for any informational/listing/exploration question about CWEs.

Rules of thumb:
- "Run/start/launch an attack" → start_attack.
- "Stop/cancel/kill/abort" → stop_attack (omit run_id to stop ALL active runs).
- "What's the status / what's happening / what did we run" → get_status.
- "What CWEs are available / popular / untried / haven't been tried / left to try / what's the top X" → list_cwes. NEVER call start_attack to answer an informational question. Only call start_attack when the user clearly wants action.
- Anything else → answer directly.

For start_attack: only set cwe_id if the user explicitly named a CWE (by ID like "CWE-352" or by name like "CSRF", "SQL injection"). For generic asks like "run an attack" or "start a scan", omit cwe_id entirely — the server will pick the next applicable CWE.

CRITICAL: Call start_attack AT MOST ONCE per user message. Never queue extra runs the user didn't ask for. If the user names one CWE, you launch exactly one run for that CWE — do not also launch related CWEs, "while we're at it" runs, or duplicates. If the user wants a batch they will say so.

Be concise. No markdown headers."""

_CHAT_TOOLS = [
    {
        'name': 'start_attack',
        'description': 'Trigger a red team attack run.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': ['inject', 'attack', 'both'],
                    'description': 'inject=code change + deploy only, attack=attack existing vuln, both=full pipeline',
                },
                'cwe_id':      {'type': 'string', 'description': 'OPTIONAL. Only set this if the user explicitly named a specific CWE (like "CWE-352" or "CSRF"). For generic requests like "run an attack" or "start a scan", LEAVE THIS BLANK so the server picks the next applicable CWE in priority order — never default to a specific CWE on your own. Any valid CWE id works, even ones outside the Top-25 — if the registry doesn\'t have it, the server fetches its name from MITRE and adds it.'},
                'instructions':{'type': 'string', 'description': 'Specific guidance for the agent.'},
            },
            'required': ['mode'],
        },
    },
    {
        'name': 'stop_attack',
        'description': 'Stop currently running attack run(s). Use when the user asks to stop, cancel, kill, or abort.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'run_id': {'type': 'string', 'description': 'OPTIONAL run ID. Omit to stop ALL currently active runs (the common case).'},
            },
            'required': [],
        },
    },
    {
        'name': 'get_status',
        'description': 'Get status of recent attack runs.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'run_id': {'type': 'string', 'description': 'Optional run ID; omit for all recent runs.'},
            },
            'required': [],
        },
    },
    {
        'name': 'list_cwes',
        'description': 'List CWEs in the registry, with rank, score, applicability, and whether they have been attacked. Use for ANY informational/listing question about CWEs (popular, untried, top-N, what is left, etc.). DO NOT use for triggering a run.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'filter':  {'type': 'string', 'enum': ['all', 'untried', 'attempted', 'applicable'],
                            'description': 'all=every CWE; untried=not in attack_log; attempted=in attack_log; applicable=applicable=TRUE only. Default: applicable.'},
                'limit':   {'type': 'integer', 'description': 'Max rows. Default 25.'},
            },
            'required': [],
        },
    },
]


def _call_tool(name, inputs, ctx=None):
    if name == 'start_attack':
        # Guard against the model queuing extra runs in a single chat turn.
        # The user's intent is one CWE per request unless they explicitly batch.
        if ctx is not None and ctx.get('start_attack_count', 0) >= 1:
            return {'error': 'A run was already launched in this turn — only one start_attack '
                             'per user message is allowed. If the user wanted more, ask them to '
                             'send another message.'}
        if ctx is not None:
            ctx['start_attack_count'] = ctx.get('start_attack_count', 0) + 1
        # Call ourselves internally
        import db, cwe_pipeline
        try:
            cwe_pipeline.sync_cwes()
        except Exception as e:
            logger.warning(f'CWE sync: {e}')
        cwe_id_override = inputs.get('cwe_id', '').strip()
        added_note = ''
        if cwe_id_override:
            # Normalize "352" or "cwe-352" → "CWE-352"
            normalized = cwe_id_override.upper()
            if normalized.isdigit():
                normalized = f'CWE-{normalized}'
            elif not normalized.startswith('CWE-'):
                m = re.match(r'^CWE-?(\d+)$', normalized)
                normalized = f'CWE-{m.group(1)}' if m else normalized
            cwe = db.get_cwe(normalized)
            if not cwe:
                # Not in our registry — try fetching from MITRE and adding it
                # so the user can target any valid CWE, not just the Top-25.
                meta = cwe_pipeline.fetch_cwe_from_mitre(normalized)
                if not meta:
                    return {'error': f'{normalized} is not in the registry and no matching CWE page found on MITRE'}
                # rank=999 / score=0 are placeholder values for non-Top-25 CWEs.
                db.upsert_cwe(meta['cwe_id'], meta['name'],
                              rank=999, score=0.0, rank_delta=0, applicable=False)
                cwe = db.get_cwe(meta['cwe_id'])
                if not cwe:
                    return {'error': f'failed to add {normalized} to registry'}
                added_note = f'Added new CWE to registry: {meta["cwe_id"]} — {meta["name"]}. '
                logger.info(f'Auto-added new CWE: {meta["cwe_id"]} ({meta["name"]})')
        else:
            cwe = db.get_next_cwe()
            if not cwe:
                return {'error': 'No applicable CWEs remaining'}

        run_id = str(uuid.uuid4())
        mode   = inputs.get('mode', 'both')
        instructions = inputs.get('instructions', '')

        with _runs_lock:
            _runs[run_id] = {
                'run_id': run_id, 'cwe_id': cwe['cwe_id'],
                'cwe_name': cwe['name'], 'mode': mode,
                'instructions': instructions, 'status': 'queued', 'detail': '',
                'steps': [], 'pending_question': None,
                'started_at': __import__('datetime').datetime.utcnow().isoformat() + 'Z',
            }
        threading.Thread(
            target=_execute_run,
            args=(run_id, cwe['cwe_id'], cwe['name'], cwe['score'], mode, instructions),
            daemon=True,
        ).start()
        result = {'run_id': run_id, 'cwe_id': cwe['cwe_id'], 'cwe_name': cwe['name'],
                  'mode': mode, 'status': 'queued'}
        if added_note:
            result['note'] = added_note.strip()
        return result

    if name == 'stop_attack':
        return _stop_run(inputs.get('run_id', '').strip())

    if name == 'get_status':
        run_id = inputs.get('run_id', '').strip()
        with _runs_lock:
            if run_id:
                return _runs.get(run_id, {'error': 'run not found'})
            return list(reversed(list(_runs.values())))[-10:]  # last 10

    if name == 'list_cwes':
        import db as _db
        from google.cloud import spanner as _sp
        f = (inputs.get('filter') or 'applicable').strip().lower()
        limit = int(inputs.get('limit') or 25)
        sql = (
            "SELECT c.cwe_id, c.name, c.rank, c.score, c.applicable, "
            "       (SELECT COUNT(*) FROM attack_log a WHERE a.cwe_id = c.cwe_id) AS attempts, "
            "       (SELECT COUNT(*) FROM attack_log a WHERE a.cwe_id = c.cwe_id AND a.status = 'confirmed') AS confirmed "
            "FROM cwe_registry c "
        )
        if f == 'untried':
            sql += "WHERE c.cwe_id NOT IN (SELECT DISTINCT cwe_id FROM attack_log) "
        elif f == 'attempted':
            sql += "WHERE c.cwe_id IN (SELECT DISTINCT cwe_id FROM attack_log) "
        elif f == 'applicable':
            sql += "WHERE c.applicable = TRUE "
        # 'all' → no extra filter
        sql += "ORDER BY c.rank ASC LIMIT @lim"
        try:
            with _db.get_db().snapshot() as snap:
                rows = list(snap.execute_sql(
                    sql,
                    params={'lim': limit},
                    param_types={'lim': _sp.param_types.INT64},
                ))
        except Exception as e:
            return {'error': f'list_cwes failed: {e}'}
        return [
            {'cwe_id': r[0], 'name': r[1], 'rank': r[2], 'score': float(r[3]),
             'applicable': r[4], 'attempts': r[5], 'confirmed_exploits': r[6]}
            for r in rows
        ]

    return {'error': f'unknown tool: {name}'}


# ── background run executor ────────────────────────────────────────────────────

def setup_workspace():
    if os.path.isdir(os.path.join(WORKSPACE_DIR, '.git')):
        result = subprocess.run(
            ['git', '-C', WORKSPACE_DIR, 'pull', '--ff-only'],
            capture_output=True, text=True,
        )
    else:
        os.makedirs(os.path.dirname(WORKSPACE_DIR), exist_ok=True)
        result = subprocess.run(
            ['git', 'clone', REPO_URL, WORKSPACE_DIR],
            capture_output=True, text=True,
        )
    if result.returncode != 0:
        raise RuntimeError(f'Git setup failed:\n{result.stderr}')


def _execute_run(run_id, cwe_id, cwe_name, cwe_score, mode, instructions, jitter_seconds=0):
    def update(status, detail=''):
        with _runs_lock:
            _runs[run_id]['status'] = status
            if detail:
                _runs[run_id]['detail'] = detail

    def on_progress(steps):
        ts = datetime.now(_PST).strftime('%H:%M:%S')
        for step in steps:
            step['ts'] = ts
        with _runs_lock:
            _runs[run_id]['steps'] = (_runs[run_id].get('steps', []) + steps)[-40:]

    reply_event = threading.Event()
    stop_event = threading.Event()
    with _runs_lock:
        _run_reply_events[run_id] = reply_event
        _run_stop_events[run_id] = stop_event

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

    final_status = 'error'
    try:
        if jitter_seconds > 0:
            delay = random.randint(0, jitter_seconds)
            if delay > 0:
                mins, secs = divmod(delay, 60)
                update('queued', f'scheduled — starting in {mins}m {secs}s')
                logger.info(f'Run {run_id} jitter delay: {delay}s')
                time.sleep(delay)
        update('setting_up')
        setup_workspace()
        # Sync deployed grocerguard source into CODEBASE_DIR so this run builds
        # on top of whatever's live (including blue team's most recent fixes),
        # rather than reverting them by rebuilding from a stale git checkout.
        try:
            from tools.inspect import inspect_and_sync_deployed
            sync_msg = inspect_and_sync_deployed('grocerguard')
            logger.info(f'Run {run_id} {sync_msg}')
        except Exception as e:
            logger.warning(f'Run {run_id} inspect_and_sync failed (continuing with git checkout): {e}')
        update('running', f'{cwe_id} / mode={mode}')
        from agent import run_agent
        run_agent(cwe_id, cwe_name, cwe_score, mode=mode, instructions=instructions,
                  on_progress=on_progress, on_ask_user=on_ask_user, stop_event=stop_event,
                  run_id=run_id)
        if stop_event.is_set():
            update('stopped', 'stopped by user')
            final_status = 'stopped'
        else:
            update('done')
            final_status = 'done'
    except Exception as e:
        logger.exception(f'Run {run_id} failed')
        update('error', str(e))
    finally:
        _run_reply_events.pop(run_id, None)
        _run_stop_events.pop(run_id, None)
        # Persist completed run to Spanner
        try:
            import db
            from datetime import datetime as _dt
            with _runs_lock:
                run = _runs.get(run_id, {})
                started_str = run.get('started_at', '')
                started = _dt.fromisoformat(started_str.replace('Z', '+00:00')) if started_str else _dt.utcnow()
                run_instructions = (
                    f'{cwe_id} / mode={mode}'
                    + (f' / {instructions[:200]}' if instructions else '')
                )
                db.save_agent_run(
                    run_id=run_id,
                    team='red',
                    status=final_status,
                    instructions=run_instructions,
                    detail=run.get('detail', ''),
                    gather_findings='',
                    steps=run.get('steps', []),
                    started_at=started,
                )
            logger.info(f'Run {run_id} persisted to agent_runs')
        except Exception as e:
            logger.warning(f'Run {run_id} save_agent_run failed: {e}')


# ── auth helper ───────────────────────────────────────────────────────────────

def _check_auth():
    if not API_KEY:
        return None
    if request.headers.get('Authorization', '') != f'Bearer {API_KEY}':
        return jsonify({'error': 'unauthorized'}), 401
    return None


# ── routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/chat', methods=['POST'])
@limiter.limit('12 per minute')
@limiter.limit('100 per hour')
def chat():
    data     = request.get_json(silent=True) or {}
    user_msg = data.get('message', '').strip()
    history  = data.get('history', [])

    if not user_msg:
        return jsonify({'error': 'empty message'}), 400

    messages = history + [{'role': 'user', 'content': user_msg}]
    chat_ctx: dict = {}

    while True:
        response = _anthropic.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=1024,
            system=_CHAT_SYSTEM,
            tools=_CHAT_TOOLS,
            messages=messages,
        )
        messages.append({'role': 'assistant', 'content': response.content})

        if response.stop_reason == 'end_turn':
            text = next((b.text for b in response.content if hasattr(b, 'text')), '(no response)')
            started_run_id = None
            started_run_info = {}
            for m in messages:
                content = m.get('content')
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get('type') == 'tool_result':
                            try:
                                result = json.loads(block.get('content', '{}'))
                                if 'run_id' in result:
                                    started_run_id = result['run_id']
                                    started_run_info = {
                                        'cwe_id':   result.get('cwe_id', ''),
                                        'cwe_name': result.get('cwe_name', ''),
                                        'mode':     result.get('mode', ''),
                                    }
                            except Exception:
                                pass
            return jsonify({
                'reply': text,
                'history': [m for m in messages if isinstance(m.get('content'), str)],
                'started_run_id':   started_run_id,
                'started_run_info': started_run_info,
            })

        if response.stop_reason != 'tool_use':
            break

        tool_results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue
            result = _call_tool(block.name, block.input, ctx=chat_ctx)
            tool_results.append({
                'type': 'tool_result',
                'tool_use_id': block.id,
                'content': json.dumps(result),
            })
        messages.append({'role': 'user', 'content': tool_results})

    return jsonify({'reply': 'Something went wrong — please try again.', 'history': []})


@app.route('/run', methods=['POST'])
def trigger_run():
    err = _check_auth()
    if err:
        return err

    body           = request.get_json(silent=True) or {}
    instructions   = body.get('instructions', '').strip()
    mode           = body.get('mode', 'both')
    cwe_override   = body.get('cwe_id', '').strip()
    jitter_minutes = int(body.get('jitter_minutes', 0))

    if mode not in ('inject', 'attack', 'both'):
        return jsonify({'error': 'mode must be inject | attack | both'}), 400

    import db, cwe_pipeline
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
            'run_id': run_id, 'cwe_id': cwe['cwe_id'], 'cwe_name': cwe['name'],
            'mode': mode, 'instructions': instructions, 'status': 'queued', 'detail': '',
            'steps': [], 'pending_question': None,
        }
    threading.Thread(
        target=_execute_run,
        args=(run_id, cwe['cwe_id'], cwe['name'], cwe['score'], mode, instructions),
        kwargs={'jitter_seconds': jitter_minutes * 60},
        daemon=True,
    ).start()

    logger.info(f'Run {run_id} started: {cwe["cwe_id"]} mode={mode} jitter={jitter_minutes}m')
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
    if run:
        return jsonify({k: v for k, v in run.items() if not k.startswith('_')})
    # Fall back to the persisted row in agent_runs so a finished run survives
    # in-memory eviction (redeploy, container restart) instead of looking 'lost'.
    try:
        import db
        persisted = db.fetch_agent_run(run_id)
    except Exception as e:
        logger.warning(f'fetch_agent_run({run_id}) failed: {e}')
        persisted = None
    if persisted:
        return jsonify(persisted)
    return jsonify({'error': 'run not found'}), 404


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


@app.route('/runs/<run_id>/stop', methods=['POST'])
def stop_run_route(run_id):
    return jsonify(_stop_run(run_id))


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
