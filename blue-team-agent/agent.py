"""Blue team agent — SequentialAgent pipeline: Gather → Analyze → Loop(Patch, Verify)."""
import os
import logging
from datetime import datetime
from zoneinfo import ZoneInfo

_PST = ZoneInfo('America/Los_Angeles')

os.environ.setdefault('GOOGLE_GENAI_USE_VERTEXAI', '1')
os.environ.setdefault('GOOGLE_CLOUD_PROJECT', 'zhiting-personal')
os.environ.setdefault('GOOGLE_CLOUD_LOCATION', 'global')
os.environ.setdefault('GOOGLE_ADK_DISABLE_TELEMETRY', '1')
os.environ.setdefault('OTEL_SDK_DISABLED', 'true')

from google.adk.agents import Agent, SequentialAgent, LoopAgent
from google.adk import Runner
from google.adk.models.google_llm import Gemini
from google.adk.sessions import InMemorySessionService
from google.adk.tools.exit_loop_tool import exit_loop
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


def _model():
    return Gemini(model='gemini-2.5-flash', retry_options=_RETRY_OPTIONS)


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

import db
from tools.codebase import (
    list_files as _list_files,
    read_file as _read_file,
    write_file as _write_file,
    search_code as _search_code,
)
from tools.deploy import deploy as _deploy
from tools.http_client import http_request as _http_request
from tools.skills import (
    fetch_service_logs as _fetch_service_logs,
    inspect_deployed_filesystem as _inspect_deployed_filesystem,
    scan_top_cwes as _scan_top_cwes,
    search_service_logs as _search_service_logs,
)

logger = logging.getLogger(__name__)

CODEBASE_DIR = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')


# ── Tool functions ─────────────────────────────────────────────────────────────

def inspect_deployed_filesystem(service_name: str) -> str:
    """Extract the live Cloud Run container filesystem to /tmp/inspections/<service_name>/. The app source lands in /tmp/inspections/<service_name>/app/."""
    return _inspect_deployed_filesystem(service_name)

def fetch_service_logs(service_name: str, limit: int = 50) -> str:
    """Fetch recent application logs from a Cloud Run service."""
    return _fetch_service_logs(service_name, limit)

def search_service_logs(service_name: str, query: str, limit: int = 30) -> str:
    """Search Cloud Run service logs for a substring match. Use for CWE-specific forensics — e.g. 'UNION SELECT' for SQLi, '<script' for XSS, '; rm ' for command injection, '../' for path traversal, '%27' for URL-encoded quote."""
    return _search_service_logs(service_name, query, limit)

def scan_top_cwes(directory: str) -> str:
    """Run heuristic CWE pattern scans (SQLi, XSS, CMDi) on Python and HTML files in a directory."""
    return _scan_top_cwes(directory)

def list_files(directory: str = "") -> str:
    """List all source files in a directory. Pass empty string for the full codebase."""
    return _list_files(directory if directory else None)

def read_file(path: str) -> str:
    """Read the full content of a file."""
    return _read_file(path)

def search_code(pattern: str, directory: str = "") -> str:
    """Search (grep) for a pattern across .py and .html files."""
    return _search_code(pattern, directory if directory else None)

def write_file(path: str, content: str) -> str:
    """Write (overwrite) a file in the codebase with new content."""
    return _write_file(path, content)

def deploy() -> str:
    """Build and deploy the patched codebase to the grocerguard Cloud Run service."""
    result = _deploy()
    success = 'failed' not in result.lower()
    try:
        db.log_deploy(success, result)
    except Exception as e:
        logger.warning(f'log_deploy failed: {e}')
    return result

def http_request(method: str, url: str, body: str = "") -> str:
    """Make an HTTP request to the live service. Set body to empty string if not needed."""
    return str(_http_request(method=method, url=url, body=body if body else None, follow_redirects=True))

def get_recent_attacks(limit: int = 5) -> str:
    """Fetch recent red team attacks including payloads and target URLs."""
    return str(db.get_recent_attacks(limit=limit))

def get_cwe_plans() -> str:
    """Read known CWE plans from the registry, sorted by rank ascending. Each plan has cwe_id, name, rank, suspect_paths, code_patterns, log_patterns, plan_notes."""
    return str(db.get_cwe_plans())

def log_defense(attack_id: str, target_url: str, fixed: bool, evidence: str) -> str:
    """Record a successful defense to the database. Set attack_id to empty string if unknown."""
    db.log_defense(attack_id=attack_id, target_url=target_url, fixed=fixed, evidence=evidence)
    return f"Defense logged for attack_id={attack_id}"


# ── Agent instructions ─────────────────────────────────────────────────────────

_GATHER_INSTRUCTION = """
You are the Gather phase. Two steps, no investigation.

1. inspect_deployed_filesystem("grocerguard") — extract deployed source to /tmp/inspections/grocerguard/app/

2. get_cwe_plans() — read known CWE plans from the registry. Each plan has cwe_id, name, rank, suspect_paths, code_patterns, log_patterns, plan_notes.

Output: dump the plans verbatim, in the order returned (already sorted by rank ascending — top-of-list first). Do NOT investigate, do NOT prioritize beyond the registry order, do NOT add candidates that aren't in the registry. Analyze will iterate this list top-down.
"""

_ANALYZE_INSTRUCTION = f"""
You are the Analyze phase. The Gather phase produced this PLAN of candidate CWEs:

{{gather_findings}}

The deployed codebase is at /tmp/inspections/grocerguard/app/.

Execute the plan ONE CANDIDATE AT A TIME, in priority order (CANDIDATE 1, then 2, etc). For EACH candidate:

1. Read the suspect files with read_file. Trace user input from request handlers (request.args / request.form / request.json) all the way through to the dangerous sink (DB query, template render, subprocess call, file open).

2. Run the candidate's planned log searches with search_service_logs("grocerguard", <pattern>) to look for actual attack evidence in URLs and stdout.

3. Decide: is this CWE PRESENT in the CURRENT deployed code AND exploitable?
   - PRESENT means the vulnerable code pattern is actually in the file (e.g. user input flows into raw SQL via concatenation, NOT just bound as a parameter).
   - EXPLOITABLE means a payload could reach it.
   - Note: parameterized queries (`text(sql)` with `:param` placeholders bound through a params dict) are SAFE even if `text()` is used. Don't flag those.

CRITICAL: As soon as you CONFIRM ONE candidate is real, STOP IMMEDIATELY. Output the diagnosis in the format below and end your turn. Do NOT continue checking other candidates — the patch phase will fix this one, and the next pipeline run can find the next.

If a candidate is a false positive (heuristic flagged it but the code is actually safe, OR no exploit path), record it briefly in your reasoning and move to the next candidate.

Output format when you confirm:

CONFIRMED: <CWE-ID> (<name>)
File: <path relative to /tmp/inspections/grocerguard/app/, e.g. app/routes/products.py>
Line: <line number of the vulnerable code>
Vulnerable code:
<the actual snippet>
Attack evidence: <log line showing the attack URL, or "no past attack in logs but code is clearly vulnerable">
Exploit description: <how an attacker exploits it>

If ALL candidates were ruled out, output:
NO CONFIRMED VULNERABILITIES — all candidates checked. <one-line summary per candidate of why ruled out>
"""

_PATCH_INSTRUCTION = f"""
You are the Patch phase of an automated blue team security pipeline for GrocerGuard.

Diagnosis from the analysis phase:
{{diagnosis}}

The vulnerability was found in the extracted container at /tmp/inspections/grocerguard/app/<path>. Apply your fix to the equivalent file in the deployable codebase at {CODEBASE_DIR}/<path> — that directory has the Dockerfile and is what gets built and deployed.

Steps:
1. Use read_file to read the vulnerable file at its {CODEBASE_DIR}/... path
2. Use write_file to apply a minimal, surgical fix — change as few lines as possible
3. Call deploy() to build and push the patched image to the grocerguard Cloud Run service
4. If deploy fails, read the error, fix the code, and retry once
"""

_VERIFY_INSTRUCTION = """
You are the Verify phase of an automated blue team security pipeline for GrocerGuard.

Diagnosis that was patched:
{diagnosis}

Your job is to confirm the patch works using the red team's actual attack data. This is the first phase in the pipeline with access to red team intel.

Steps:
1. Call get_recent_attacks(5) to get the red team's payloads and target URLs
2. Replay those payloads against the live grocerguard service using http_request
3. If the attack is now blocked or no longer exploitable:
   - Call log_defense with attack_id, target_url, fixed=True, and evidence of the blocked response
   - Call exit_loop to complete the pipeline
4. If the attack still succeeds, describe exactly what still works — the patch phase will run again
"""


# ── Pipeline ───────────────────────────────────────────────────────────────────

gather_agent = Agent(
    name="gather",
    model=_model(),
    instruction=_GATHER_INSTRUCTION,
    tools=[inspect_deployed_filesystem, get_cwe_plans],
    output_key="gather_findings",
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

analyze_agent = Agent(
    name="analyze",
    model=_model(),
    instruction=_ANALYZE_INSTRUCTION,
    tools=[list_files, read_file, search_code, search_service_logs],
    output_key="diagnosis",
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

patch_agent = Agent(
    name="patch",
    model=_model(),
    instruction=_PATCH_INSTRUCTION,
    tools=[list_files, read_file, search_code, search_service_logs, fetch_service_logs, write_file, http_request, deploy],
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

verify_agent = Agent(
    name="verify",
    model=_model(),
    instruction=_VERIFY_INSTRUCTION,
    tools=[get_recent_attacks, http_request, log_defense, exit_loop],
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

patch_verify_loop = LoopAgent(
    name="patch_verify",
    sub_agents=[patch_agent, verify_agent],
    max_iterations=3,
)

blue_team_agent = SequentialAgent(
    name="blue_team",
    sub_agents=[gather_agent, analyze_agent, patch_verify_loop],
)


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_agent(instructions: str = '', on_progress=None, on_ask_user=None, on_state=None):
    """Run the pipeline. on_state(key, value) is called for output_key writes (e.g. gather_findings)."""
    logger.info('Starting Blue Team Agent pipeline')

    def _stamp(steps):
        ts = datetime.now(_PST).strftime('%H:%M:%S')
        for s in steps:
            s.setdefault('ts', ts)
        return steps

    user_message = 'Find the recently injected vulnerability, fix it, verify the fix, and log your defense.'
    if instructions:
        user_message += f'\nAdditional instructions:\n{instructions}'

    if on_progress:
        on_progress(_stamp([{'type': 'text', 'text': 'Blue team pipeline starting: Gather → Analyze → Patch/Verify'}]))

    try:
        from google.genai import types
        import asyncio

        async def _run():
            session_service = InMemorySessionService()
            runner = Runner(
                app_name="blue_team_app",
                agent=blue_team_agent,
                session_service=session_service,
            )
            session = await session_service.create_session(
                app_name="blue_team_app", user_id="system"
            )

            reply = ""
            last_author = None
            async for event in runner.run_async(
                user_id="system",
                session_id=session.id,
                new_message=types.Content(
                    role="user", parts=[types.Part.from_text(text=user_message)]
                ),
            ):
                if not event.content:
                    continue
                author = getattr(event, 'author', '')

                if author and author != last_author:
                    logger.info(f'[pipeline] phase → {author}')
                    last_author = author

                for part in event.content.parts:
                    if hasattr(part, 'function_call') and part.function_call:
                        fc = part.function_call
                        args_preview = str(dict(fc.args))[:200]
                        logger.info(f'[{author}] tool_call: {fc.name}({args_preview})')
                        step = {
                            'type': 'tool_call',
                            'agent': author,
                            'text': f'{fc.name}({args_preview})',
                        }
                        if on_progress:
                            on_progress(_stamp([step]))
                    elif hasattr(part, 'function_response') and part.function_response:
                        fr = part.function_response
                        resp = fr.response or {}
                        raw = resp.get('result') or resp.get('output', '')
                        preview = str(raw)[:200]
                        logger.info(f'[{author}] tool_result: {fr.name} → {preview}')
                    elif hasattr(part, 'text') and part.text:
                        if event.is_final_response():
                            logger.info(f'[{author}] final_response: {part.text[:400]}')
                            reply += part.text
                        else:
                            logger.info(f'[{author}] text: {part.text[:200]}')
                        step = {
                            'type': 'text',
                            'agent': author,
                            'text': part.text[:300],
                        }
                        if on_progress:
                            on_progress(_stamp([step]))

                # After each event, surface any newly written output_keys.
                if on_state and event.actions and event.actions.state_delta:
                    for k, v in event.actions.state_delta.items():
                        if isinstance(v, str):
                            on_state(k, v)
            return reply

        reply = asyncio.run(_run())

        logger.info('Blue team pipeline complete')
        if on_progress and reply:
            on_progress(_stamp([{'type': 'text', 'text': f'Pipeline complete.\n\n{reply}'}]))

    except Exception as e:
        logger.exception("Agent pipeline failed")
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Pipeline failed: {e}'}])
