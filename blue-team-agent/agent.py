"""Blue team agent — SequentialAgent pipeline: Gather → Analyze → Loop(Patch, Verify)."""
import os
import logging

os.environ.setdefault('GOOGLE_GENAI_USE_VERTEXAI', '1')
os.environ.setdefault('GOOGLE_CLOUD_PROJECT', 'zhiting-personal')
os.environ.setdefault('GOOGLE_CLOUD_LOCATION', 'us-central1')
os.environ.setdefault('GOOGLE_ADK_DISABLE_TELEMETRY', '1')
os.environ.setdefault('OTEL_SDK_DISABLED', 'true')

from google.adk.agents import Agent, SequentialAgent, LoopAgent
from google.adk import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.exit_loop_tool import exit_loop

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

def log_defense(attack_id: str, target_url: str, fixed: bool, evidence: str) -> str:
    """Record a successful defense to the database. Set attack_id to empty string if unknown."""
    db.log_defense(attack_id=attack_id, target_url=target_url, fixed=fixed, evidence=evidence)
    return f"Defense logged for attack_id={attack_id}"


# ── Agent instructions ─────────────────────────────────────────────────────────

_GATHER_INSTRUCTION = f"""
You are the Gather phase of an automated blue team security pipeline for GrocerGuard, a Flask/Cloud Spanner grocery web app on Cloud Run.

Your job is to collect raw forensic evidence from the live deployed service. You have NO knowledge of what the red team did — discover it purely from the deployed artifact and logs.

Complete all three steps:

1. Call inspect_deployed_filesystem("grocerguard") to extract the live container to /tmp/inspections/grocerguard/. The app source will be at /tmp/inspections/grocerguard/app/.

2. Call scan_top_cwes("/tmp/inspections/grocerguard/app") to run heuristic CWE checks on the extracted source.

3. Call fetch_service_logs("grocerguard", 100) to look for anomalous HTTP request patterns in recent logs.

Output a structured findings report:
- Which files and line numbers were flagged by the CWE scan and what pattern triggered
- Any anomalies in logs (unusual URLs, error spikes, injection-looking query parameters)
- Your best assessment of the most likely vulnerability type and location
"""

_ANALYZE_INSTRUCTION = f"""
You are the Analyze phase of an automated blue team security pipeline for GrocerGuard.

The Gather phase produced these findings:
{{gather_findings}}

The deployed codebase has been extracted to /tmp/inspections/grocerguard/app/. Use list_files, read_file, and search_code to investigate it.

Your job is to pinpoint the exact injected vulnerability:
1. Start from the files and patterns flagged in the gather findings
2. Read suspicious files in full — trace user input from HTTP request parameters through to database queries and Jinja2 template rendering
3. Confirm the vulnerability is real and exploitable, not a heuristic false positive
4. Identify the precise file path, line number, CWE ID, and the exact vulnerable code

Output a concise diagnosis:
- File path relative to /tmp/inspections/grocerguard/app/ (e.g. app/routes/products.py) and line number
- CWE ID and name
- The vulnerable code snippet
- How an attacker would exploit it
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
    model="gemini-2.5-flash",
    instruction=_GATHER_INSTRUCTION,
    tools=[inspect_deployed_filesystem, scan_top_cwes, fetch_service_logs],
    output_key="gather_findings",
)

analyze_agent = Agent(
    name="analyze",
    model="gemini-2.5-flash",
    instruction=_ANALYZE_INSTRUCTION,
    tools=[list_files, read_file, search_code],
    output_key="diagnosis",
)

patch_agent = Agent(
    name="patch",
    model="gemini-2.5-flash",
    instruction=_PATCH_INSTRUCTION,
    tools=[read_file, write_file, deploy],
)

verify_agent = Agent(
    name="verify",
    model="gemini-2.5-flash",
    instruction=_VERIFY_INSTRUCTION,
    tools=[get_recent_attacks, http_request, log_defense, exit_loop],
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

def run_agent(instructions: str = '', on_progress=None, on_ask_user=None):
    logger.info('Starting Blue Team Agent pipeline')

    user_message = 'Find the recently injected vulnerability, fix it, verify the fix, and log your defense.'
    if instructions:
        user_message += f'\nAdditional instructions:\n{instructions}'

    if on_progress:
        on_progress([{'type': 'text', 'text': 'Blue team pipeline starting: Gather → Analyze → Patch/Verify'}])

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
                        args_preview = str(dict(fc.args))[:300]
                        logger.info(f'[{author}] tool_call: {fc.name}({args_preview})')
                        step = {
                            'type': 'tool_call',
                            'agent': author,
                            'text': f'[{author}] {fc.name}({args_preview})',
                        }
                        if on_progress:
                            on_progress([step])
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
                            'text': f'[{author}] {part.text[:400]}',
                        }
                        if on_progress:
                            on_progress([step])
            return reply

        reply = asyncio.run(_run())

        logger.info('Blue team pipeline complete')
        if on_progress and reply:
            on_progress([{'type': 'text', 'text': f'Pipeline complete.\n\n{reply}'}])

    except Exception as e:
        logger.exception("Agent pipeline failed")
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Pipeline failed: {e}'}])
