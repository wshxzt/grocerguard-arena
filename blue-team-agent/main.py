"""Blue team agent service — accepts HTTP requests and runs autonomous background scans."""
import os
import json
import logging
import threading
import time
import uuid

# Must be set before any ADK imports so the SDK uses Vertex AI instead of AI Studio.
os.environ.setdefault('GOOGLE_GENAI_USE_VERTEXAI', '1')
os.environ.setdefault('GOOGLE_CLOUD_PROJECT', 'zhiting-personal')
os.environ.setdefault('GOOGLE_CLOUD_LOCATION', 'global')
os.environ.setdefault('GOOGLE_ADK_DISABLE_TELEMETRY', '1')
os.environ.setdefault('OTEL_SDK_DISABLED', 'true')

from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.cloud import spanner

from google.adk.agents import Agent
from google.adk import Runner
from google.adk.models.google_llm import Gemini
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

MODEL_TIMEOUT_MS = 30000

_RETRY_OPTIONS = genai_types.HttpRetryOptions(
    attempts=4,
    initial_delay=2.0,
    max_delay=30.0,
    exp_base=2.0,
    jitter=0.1,
    http_status_codes=[429, 500, 502, 503, 504],
)


def _before_model(callback_context, llm_request):
    """Force a 30s timeout on every Gemini call AND log the request."""
    if llm_request.config is None:
        llm_request.config = genai_types.GenerateContentConfig()
    if llm_request.config.http_options is None:
        llm_request.config.http_options = genai_types.HttpOptions()
    llm_request.config.http_options.timeout = MODEL_TIMEOUT_MS

    agent_name = getattr(callback_context, 'agent_name', '?')
    contents = llm_request.contents or []
    last_msg = ''
    if contents:
        for part in (contents[-1].parts or []):
            if getattr(part, 'function_response', None):
                last_msg = f'[fn_response] {part.function_response.name}'
                break
            if getattr(part, 'function_call', None):
                last_msg = f'[fn_call] {part.function_call.name}'
                break
            if getattr(part, 'text', None):
                last_msg = part.text
                break
    tools = list(llm_request.tools_dict.keys()) if llm_request.tools_dict else []
    logger.info(
        f'[{agent_name}] LLM REQUEST → model={llm_request.model} '
        f'contents={len(contents)} tools={tools} last_msg={last_msg[:200]!r}'
    )
    return None


def _after_model(callback_context, llm_response):
    """Log the model response (parts, finish reason, token usage, errors)."""
    agent_name = getattr(callback_context, 'agent_name', '?')

    parts_summary = []
    if llm_response.content and llm_response.content.parts:
        for part in llm_response.content.parts:
            fc = getattr(part, 'function_call', None)
            if fc:
                args_preview = str(dict(fc.args or {}))[:200]
                parts_summary.append(f'fn_call={fc.name}({args_preview})')
                continue
            text = getattr(part, 'text', None)
            if text:
                parts_summary.append(f'text={text[:200]!r}')

    usage = ''
    um = llm_response.usage_metadata
    if um:
        usage = (f' tokens={getattr(um, "prompt_token_count", "?")}'
                 f'/{getattr(um, "candidates_token_count", "?")}'
                 f'/{getattr(um, "total_token_count", "?")}')

    err = ''
    if llm_response.error_code:
        err = f' ERROR={llm_response.error_code}: {llm_response.error_message}'

    logger.info(
        f'[{agent_name}] LLM RESPONSE → finish={llm_response.finish_reason}{usage}{err} '
        f'parts=[{"; ".join(parts_summary) or "(empty)"}]'
    )
    return None

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

API_KEY = os.environ.get('AGENT_API_KEY', '')

_runs: dict[str, dict] = {}
_runs_lock = threading.Lock()
_run_reply_events: dict[str, threading.Event] = {}

# ── Chat System ────────────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are the GrocerGuard Blue Team assistant, running at the blue-team-agent service.
You help security engineers troubleshoot, defend, and patch the GrocerGuard application.

When the user asks to start/run/launch a scan, use trigger_scan.
When the user asks about status or results, use get_status.

PLAN REFINEMENT RECOVERY:
At the end of each scan, the Refine sub-agent sometimes proposes additions to a CWE's plan_notes or code_patterns. The user approves them via a Yes/No bubble. If they miss that window (the bubble closes, container restarts, etc.), the proposal is preserved in the run's steps_json and can be retrieved later.

Two tools:
- list_pending_refinements() — lists what's pending. Use only if the user wants to BROWSE proposals first.
- apply_pending_refinement(cwe_id) — looks up + applies the most recent proposal for ONE CWE atomically. Use this when the user names the CWE.

Routing:
- "What refinements are pending?" / "what's missing?" → list_pending_refinements, then summarize.
- "apply CWE-X" / "save CWE-X" / "yes apply that one" with a clear CWE id → apply_pending_refinement(cwe_id="CWE-X"). Do NOT call list_pending_refinements first; do NOT loop.
- After apply_pending_refinement returns, write a short summary in plain text covering: (a) which CWE was updated, (b) the plan_notes line that was appended (quote it verbatim if non-empty), (c) the code_patterns added (each one on its own line, in backticks). Mention which run_id the proposal came from. Then END YOUR TURN. Do not re-call any tool unless the user asks for something new.

Never apply without an explicit CWE id from the user. If they say "apply it" but only one CWE was previously listed, that's enough — call apply_pending_refinement with that id.

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


_REFINEMENT_RE = __import__('re').compile(
    r'PLAN_REFINEMENT:\s*\n'
    r'\s*cwe_id:\s*(?P<cwe_id>CWE-\d+)\s*\n'
    r'\s*new_code_patterns:\s*(?P<patterns>.*?)\n'
    r'\s*new_plan_notes_addition:\s*(?P<notes>.*?)(?=\n\s*reasoning:|\n\s*PLAN_REFINEMENT:|\Z)',
    __import__('re').DOTALL | __import__('re').IGNORECASE,
)


def _parse_refinements_from_steps(steps):
    """Find PLAN_REFINEMENT blocks in a run's saved step list. Returns a list
    of dicts: {cwe_id, code_patterns: [...], plan_notes_addition: '...'}."""
    import ast
    out = []
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        text = step.get('text', '') or ''
        if 'PLAN_REFINEMENT:' not in text:
            continue
        for m in _REFINEMENT_RE.finditer(text):
            patterns_raw = m.group('patterns').strip()
            patterns = []
            if patterns_raw and patterns_raw not in ('[]', 'null', 'None'):
                try:
                    parsed = ast.literal_eval(patterns_raw)
                    if isinstance(parsed, list):
                        patterns = [str(p) for p in parsed if p]
                except Exception:
                    pass
            notes = m.group('notes').strip().strip('"').strip("'")
            out.append({
                'cwe_id': m.group('cwe_id').upper(),
                'code_patterns': patterns,
                'plan_notes_addition': notes,
            })
    return out


def list_pending_refinements(limit: int = 5) -> str:
    """Look up recent blue team runs and return PLAN_REFINEMENT proposals that
    haven't been applied yet. Use this when the user asks to recover a
    refinement they missed approving in the bubble."""
    import db
    sql = ("SELECT id, started_at, steps_json FROM agent_runs "
           "WHERE team='blue' ORDER BY started_at DESC LIMIT @lim")
    try:
        with db.get_db().snapshot() as snap:
            rows = list(snap.execute_sql(
                sql, params={'lim': int(limit)},
                param_types={'lim': spanner.param_types.INT64},
            ))
    except Exception as e:
        return json.dumps({'error': f'list_pending_refinements failed: {e}'})

    # Map cwe_id → current plan_notes/code_patterns once, to filter out
    # refinements already applied.
    current = {}
    try:
        with db.get_db().snapshot() as snap:
            for r in snap.execute_sql(
                'SELECT cwe_id, plan_notes, code_patterns FROM cwe_registry'
            ):
                current[r[0]] = {
                    'plan_notes':    r[1] or '',
                    'code_patterns': list(r[2] or []),
                }
    except Exception as e:
        logger.warning(f'cwe_registry preload failed: {e}')

    pending = []
    seen = set()  # (run_id, cwe_id) — dedupe within a single run
    for run_id, started_at, steps_json in rows:
        try:
            steps = json.loads(steps_json) if steps_json else []
        except Exception:
            steps = []
        for ref in _parse_refinements_from_steps(steps):
            key = (run_id, ref['cwe_id'])
            if key in seen:
                continue
            seen.add(key)
            cur = current.get(ref['cwe_id'], {'plan_notes': '', 'code_patterns': []})
            notes_already = (ref['plan_notes_addition']
                             and ref['plan_notes_addition'] in cur['plan_notes'])
            patterns_missing = [p for p in ref['code_patterns']
                                if p not in cur['code_patterns']]
            if notes_already and not patterns_missing:
                continue  # already applied
            pending.append({
                'source_run_id':         run_id,
                'started_at':            started_at.isoformat() if started_at else '',
                'cwe_id':                ref['cwe_id'],
                'code_patterns':         ref['code_patterns'],
                'patterns_to_add':       patterns_missing,
                'plan_notes_addition':   ref['plan_notes_addition'],
                'notes_already_applied': bool(notes_already),
            })
    return json.dumps(pending)


def apply_pending_refinement(cwe_id: str) -> str:
    """Apply the most recent pending PLAN_REFINEMENT for a single CWE to the
    registry. Looks up the proposal from the saved blue agent_runs (so it
    works even after the bubble's approval window closed) and writes the
    additions to cwe_registry.

    Use this after the user explicitly names which CWE to apply, e.g.
    "apply CWE-306" or "save the CWE-89 refinement". Do NOT call this just
    because list_pending_refinements returned something — wait for the user."""
    import db
    cwe_id = (cwe_id or '').strip().upper()
    if not cwe_id.startswith('CWE-'):
        return json.dumps({'error': f'bad cwe_id: {cwe_id!r}'})

    try:
        pending = json.loads(list_pending_refinements(limit=10))
    except Exception as e:
        return json.dumps({'error': f'lookup failed: {e}'})
    if isinstance(pending, dict) and 'error' in pending:
        return json.dumps(pending)

    match = next((p for p in pending if p.get('cwe_id') == cwe_id), None)
    if not match:
        return json.dumps({'error': f'no pending refinement found for {cwe_id} '
                                    f'(it may already be applied, or no recent '
                                    f'run proposed one)'})

    notes = match.get('plan_notes_addition') or ''
    patterns = match.get('patterns_to_add') or []
    results = {
        'cwe_id': cwe_id,
        'source_run_id': match.get('source_run_id', ''),
        'plan_notes_added': '',
        'plan_notes_status': '',
        'patterns_added': [],
        'patterns_status': '',
    }
    if notes.strip() and not match.get('notes_already_applied'):
        results['plan_notes_status'] = db.update_cwe_plan_notes(cwe_id, notes)
        results['plan_notes_added']  = notes
    if patterns:
        results['patterns_status'] = db.update_cwe_code_patterns(cwe_id, patterns)
        results['patterns_added']  = patterns
    if not results['plan_notes_added'] and not results['patterns_added']:
        return json.dumps({'error': f'{cwe_id} refinement is already fully applied'})
    return json.dumps(results)


chat_agent = Agent(
    name="chat_assistant",
    model=Gemini(model='gemini-2.5-flash', retry_options=_RETRY_OPTIONS),
    instruction=_CHAT_SYSTEM,
    tools=[trigger_scan, get_status, list_pending_refinements, apply_pending_refinement],
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

# ── Background Execution & Autonomous Scanner ──────────────────────────────────

def _execute_run(run_id, instructions=''):
    logger.info(f'Run {run_id} starting (instructions: {instructions[:80]!r})')

    last_progress = [time.time()]
    stop_watchdog = threading.Event()
    state_captures = {}  # output_key → value, captured from agent state deltas

    def update(status, detail=''):
        with _runs_lock:
            _runs[run_id]['status'] = status
            if detail:
                _runs[run_id]['detail'] = detail
        logger.info(f'Run {run_id} status → {status}' + (f': {detail[:120]}' if detail else ''))

    def on_progress(steps):
        last_progress[0] = time.time()
        with _runs_lock:
            _runs[run_id]['steps'] = (_runs[run_id].get('steps', []) + steps)[-40:]
        for step in steps:
            stype = step.get('type', '') if isinstance(step, dict) else ''
            stext = step.get('text', str(step)) if isinstance(step, dict) else str(step)
            if stype == 'tool_call':
                logger.info(f'Run {run_id} step [{stype}]: {stext[:200]}')

    # Tools known to take a while; the watchdog gives them a longer leash.
    _SLOW_TOOLS = {'inspect_deployed_filesystem', 'deploy'}

    def watchdog():
        last_warned_at = 0
        while not stop_watchdog.wait(15):
            with _runs_lock:
                run = _runs.get(run_id, {})
                status = run.get('status', '')
                last_step = run.get('steps', [])[-1] if run.get('steps') else None
            if status != 'running':
                continue
            idle = int(time.time() - last_progress[0])

            last_text = last_step.get('text', '') if last_step else ''
            is_tool = last_step and last_step.get('type') == 'tool_call'
            is_slow_tool = is_tool and any(t in last_text for t in _SLOW_TOOLS)

            if is_slow_tool:
                threshold, label = 360, 'slow tool'
            elif is_tool:
                threshold, label = 120, 'tool call'
            else:
                threshold, label = 60, 'Gemini call (silent 429 retry / slow response)'

            if idle >= threshold and (time.time() - last_warned_at) >= 60:
                last_preview = last_text[:120] if is_tool else ''
                msg = (f'⏳ No progress for {idle}s — waiting on {label}'
                       + (f': {last_preview}' if last_preview else ''))
                logger.warning(f'Run {run_id} watchdog: {msg}')
                with _runs_lock:
                    _runs[run_id]['steps'] = (
                        _runs[run_id].get('steps', []) +
                        [{'type': 'text', 'agent': 'watchdog', 'text': msg}]
                    )[-40:]
                last_warned_at = time.time()

    reply_event = threading.Event()
    with _runs_lock:
        _run_reply_events[run_id] = reply_event

    def on_ask_user(question):
        reply_event.clear()
        with _runs_lock:
            _runs[run_id]['pending_question'] = question
            _runs[run_id]['status'] = 'waiting'
        logger.info(f'Run {run_id} waiting for user input: {question[:80]}')
        got = reply_event.wait(timeout=300)  # 5 minutes
        with _runs_lock:
            reply = _runs[run_id].pop('pending_reply', '')
            _runs[run_id]['pending_question'] = None
            _runs[run_id]['status'] = 'running'
        if not got:
            logger.info(f'Run {run_id} ask_user timed out after 300s — treating as no reply')
            return ''
        logger.info(f'Run {run_id} got user reply: {reply[:80]}')
        return reply

    threading.Thread(target=watchdog, daemon=True).start()

    def on_cwe_progress(cwe_id, status, note=''):
        with _runs_lock:
            progress = _runs[run_id].setdefault('cwe_progress', {})
            progress[cwe_id] = {'status': status, 'note': note}

    def on_state(key, value):
        state_captures[key] = value
        # Parse CWE plan / progress so the bubble can render a checklist.
        import re
        if key == 'gather_findings' and isinstance(value, str):
            seen, ordered = set(), []
            for m in re.finditer(r'CWE-\d+', value):
                c = m.group(0)
                if c not in seen:
                    seen.add(c)
                    ordered.append(c)
            # Filter to only CWEs that actually have a plan in the registry.
            # Unplanned CWEs are opportunistic plan-seeding targets — the bubble
            # checklist focuses on the deterministic, planned ones.
            try:
                import db as _db
                planned_set = {p['cwe_id'] for p in _db.get_cwe_plans()
                               if p.get('is_planned')}
                ordered = [c for c in ordered if c in planned_set]
            except Exception as e:
                logger.warning(f'planned_cwes filter failed, falling back to all: {e}')
            with _runs_lock:
                _runs[run_id]['planned_cwes'] = ordered
        elif key == 'diagnosis' and isinstance(value, str):
            up = value.upper()
            if 'NO CONFIRMED' in up:
                confirmed = []
            else:
                confirmed = []
                for pat in (r'###\s*\d+\.\s*(CWE-\d+)', r'CONFIRMED[^\n]*?(CWE-\d+)'):
                    confirmed = re.findall(pat, value)
                    if confirmed:
                        break
                # Dedup, preserve order
                seen, deduped = set(), []
                for c in confirmed:
                    if c not in seen:
                        seen.add(c)
                        deduped.append(c)
                confirmed = deduped
            with _runs_lock:
                _runs[run_id]['confirmed_cwes'] = confirmed

    final_status = 'error'
    try:
        update('running')
        from agent import run_agent
        run_agent(instructions=instructions, on_progress=on_progress,
                  on_ask_user=on_ask_user, on_state=on_state,
                  on_cwe_progress=on_cwe_progress, run_id=run_id)
        update('done')
        final_status = 'done'
        logger.info(f'Run {run_id} finished successfully')
    except Exception as e:
        logger.exception(f'Run {run_id} failed')
        update('error', str(e))
    finally:
        stop_watchdog.set()
        _run_reply_events.pop(run_id, None)
        # Persist completed run to Spanner
        try:
            import db
            from datetime import datetime as _dt
            with _runs_lock:
                run = _runs.get(run_id, {})
                started_str = run.get('started_at', '')
                started = _dt.fromisoformat(started_str.replace('Z', '+00:00')) if started_str else _dt.utcnow()
                db.save_agent_run(
                    run_id=run_id,
                    team='blue',
                    status=final_status,
                    instructions=run.get('instructions', ''),
                    detail=run.get('detail', ''),
                    gather_findings=state_captures.get('gather_findings', ''),
                    steps=run.get('steps', []),
                    started_at=started,
                )
            logger.info(f'Run {run_id} persisted to agent_runs')
        except Exception as e:
            logger.warning(f'Run {run_id} save_agent_run failed: {e}')



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

        # ADK handles tool loop internally
        from google.genai import types
        import asyncio

        async def _run_chat():
            session_service = InMemorySessionService()
            runner = Runner(app_name="blue_team_app", agent=chat_agent, session_service=session_service)
            session = await session_service.create_session(app_name="blue_team_app", user_id="system")

            reply = ""
            started_run_id = None
            async for event in runner.run_async(
                user_id="system",
                session_id=session.id,
                new_message=types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
            ):
                if not event.content:
                    continue
                for part in event.content.parts:
                    if hasattr(part, 'function_response') and part.function_response:
                        fr = part.function_response
                        if fr.name == 'trigger_scan':
                            try:
                                # ADK wraps string return values under 'result' or 'output'
                                resp = fr.response or {}
                                raw = resp.get('result') or resp.get('output', '')
                                data = json.loads(raw) if isinstance(raw, str) else raw
                                started_run_id = data.get('run_id')
                            except Exception:
                                pass
                    elif hasattr(part, 'text') and part.text:
                        reply += part.text
            return reply, started_run_id

        reply, started_run_id = asyncio.run(_run_chat())

        frontend_history = []
        for m in history:
            if isinstance(m, dict) and "content" in m and isinstance(m["content"], str):
                r = "user" if m.get("role") == "user" else "assistant"
                frontend_history.append({"role": r, "content": m["content"]})

        return jsonify({
            'reply': reply or "(no response)",
            'history': frontend_history,
            'started_run_id': started_run_id,
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
    with _runs_lock:
        return jsonify(list(reversed(list(_runs.values()))))


@app.route('/runs/<run_id>', methods=['GET'])
def get_run(run_id):
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


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8081)))
