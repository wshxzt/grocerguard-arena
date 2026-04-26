"""Google ADK blue team agent with tool use agentic loop."""
import os
import logging
from typing import Optional

# Use Vertex AI (GCP project) for billing instead of AI Studio
os.environ.setdefault('GOOGLE_GENAI_USE_VERTEXAI', '1')
os.environ.setdefault('GOOGLE_CLOUD_PROJECT', 'zhiting-personal')
os.environ.setdefault('GOOGLE_CLOUD_LOCATION', 'us-central1')
# Disable ADK telemetry (avoids 403 on Cloud Monitoring for dev environments)
os.environ.setdefault('GOOGLE_ADK_DISABLE_TELEMETRY', '1')
os.environ.setdefault('OTEL_SDK_DISABLED', 'true')

from google.adk.agents import Agent
from google.adk import Runner
from google.adk.sessions import InMemorySessionService

import db
from tools.codebase import list_files as _list_files, read_file as _read_file, write_file as _write_file, search_code as _search_code
from tools.deploy import deploy as _deploy
from tools.http_client import http_request as _http_request
from tools.skills import fetch_service_logs as _fetch_service_logs, inspect_deployed_filesystem as _inspect_deployed_filesystem, scan_top_cwes as _scan_top_cwes

logger = logging.getLogger(__name__)

_SYSTEM_BASE = """You are an automated blue team security agent for GrocerGuard, a Flask/Cloud Spanner grocery web app.

Guidelines:
- You do NOT know the exact vulnerability that was injected. You must scan the codebase (e.g. check for missing input validation, unescaped queries, etc.) to find recent vulnerabilities.
- You have access to a repository of specialized defensive skills. Use `list_skills` to see what is available, and `load_skill` to read the instructions for a specific skill before attempting complex tasks like inspecting deployments or scanning for vulnerabilities.
- Make surgical changes — modify as few files as needed to patch the vulnerability.
- After deploying the patch, verify it by calling get_recent_attacks to get red team payloads, and use http_request to test if the attack is now blocked or mitigated.
- If deployment fails, read the error, fix the code, and retry once.
- Once you verify the patch, call log_defense to record your success.
"""

def list_files(directory: str = "") -> str:
    """List all source files in the GrocerGuard codebase. Pass empty string to list from root."""
    return _list_files(directory if directory else None)

def read_file(path: str) -> str:
    """Read the full content of a file in the codebase."""
    return _read_file(path)

def search_code(pattern: str, directory: str = "") -> str:
    """Search (grep) for a pattern across .py and .html files."""
    return _search_code(pattern, directory if directory else None)

def write_file(path: str, content: str) -> str:
    """Write (overwrite) a file in the codebase with new content."""
    return _write_file(path, content)

def deploy() -> str:
    """Build the modified codebase and deploy it to the grocerguard-redteam Cloud Run service. Returns the service URL or an error message."""
    result = _deploy()
    success = 'failed' not in result.lower()
    try:
        db.log_deploy(success, result)
    except Exception as e:
        logger.warning(f'log_deploy failed: {e}')
    return result

def http_request(method: str, url: str, body: str = "") -> str:
    """Make an HTTP request to the deployed service or any URL to verify the fix. Set body to empty string if not needed."""
    return str(_http_request(
        method=method,
        url=url,
        body=body if body else None,
        follow_redirects=True,
    ))

def get_recent_attacks(limit: int = 5) -> str:
    """Fetch recent attacks performed by the red team, including their exploit payloads and target URLs, so you can test if your patch works."""
    return str(db.get_recent_attacks(limit=limit))

def log_defense(attack_id: str, target_url: str, fixed: bool, evidence: str) -> str:
    """Record the defense result to the database. Set attack_id to empty string if unknown."""
    db.log_defense(
        attack_id=attack_id,
        target_url=target_url,
        fixed=fixed,
        evidence=evidence
    )
    return f"Defense logged for attack_id={attack_id}"

def execute_fetch_service_logs(service_name: str, limit: int = 50) -> str:
    """Underlying tool to fetch recent application logs from a Cloud Run service."""
    return _fetch_service_logs(service_name, limit)

def execute_inspect_deployed_filesystem(service_name: str) -> str:
    """Underlying tool to find the currently deployed image for a service and extract its filesystem to /tmp/inspections/<service_name>."""
    return _inspect_deployed_filesystem(service_name)

def execute_scan_top_cwes(directory: str = "") -> str:
    """Underlying tool to run localized heuristic scans on the codebase for Top CWEs."""
    return _scan_top_cwes(directory)

def list_skills() -> str:
    """List available modular ADK skills that you can load for specialized instructions."""
    skills_dir = os.path.join(os.path.dirname(__file__), 'skills')
    if not os.path.exists(skills_dir):
        return "No skills directory found."
    skills = [d for d in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, d))]
    return "Available skills:\\n- " + "\\n- ".join(skills)

def load_skill(skill_name: str) -> str:
    """Load the SKILL.md instructions for a specific skill. You MUST load a skill before trying to use its underlying tools."""
    skill_file = os.path.join(os.path.dirname(__file__), 'skills', skill_name, 'SKILL.md')
    if not os.path.exists(skill_file):
        return f"Skill '{skill_name}' not found."
    with open(skill_file, 'r') as f:
        return f.read()

blue_team_agent = Agent(
    name="blue_team",
    model="gemini-2.5-flash",
    instruction=_SYSTEM_BASE,
    tools=[list_files, read_file, search_code, write_file, deploy, http_request, get_recent_attacks, log_defense, 
           execute_fetch_service_logs, execute_inspect_deployed_filesystem, execute_scan_top_cwes, list_skills, load_skill]
)

def run_agent(instructions: str = '', on_progress=None, on_ask_user=None):
    logger.info('Starting Blue Team Agent (ADK)')

    user_message = 'Please find the recently injected vulnerability, fix it, verify the fix, and log your defense.'
    if instructions:
        user_message += f'\\nAdditional instructions:\\n{instructions}'

    if on_progress:
        on_progress([{'type': 'text', 'text': 'Agent started running...'}])

    try:
        from google.genai import types
        import asyncio

        async def _run():
            session_service = InMemorySessionService()
            runner = Runner(app_name="blue_team_app", agent=blue_team_agent, session_service=session_service)
            session = await session_service.create_session(app_name="blue_team_app", user_id="system")

            reply = ""
            async for event in runner.run_async(
                user_id="system",
                session_id=session.id,
                new_message=types.Content(role="user", parts=[types.Part.from_text(text=user_message)])
            ):
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if hasattr(part, 'text') and part.text:
                            reply += part.text
            return reply

        reply = asyncio.run(_run())

        if on_progress:
            on_progress([{'type': 'text', 'text': f'Agent finished.\\n\\nFinal response:\\n{reply}'}])

    except Exception as e:
        logger.exception("Agent run failed")
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Agent failed with error: {e}'}])
