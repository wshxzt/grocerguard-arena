"""Google ADK blue team agent with tool use agentic loop."""
import os
import logging
from typing import Optional

from google.adk.agents import Agent
from google.adk.tools import tool

import db
from tools.codebase import list_files as _list_files, read_file as _read_file, write_file as _write_file, search_code as _search_code
from tools.deploy import deploy as _deploy
from tools.http_client import http_request as _http_request

logger = logging.getLogger(__name__)

_SYSTEM_BASE = """You are an automated blue team security agent for GrocerGuard, a Flask/Cloud Spanner grocery web app.

Guidelines:
- You do NOT know the exact vulnerability that was injected. You must scan the codebase (e.g. check for missing input validation, unescaped queries, etc.) to find recent vulnerabilities.
- Make surgical changes — modify as few files as needed to patch the vulnerability.
- After deploying the patch, verify it by calling get_recent_attacks to get red team payloads, and use http_request to test if the attack is now blocked or mitigated.
- If deployment fails, read the error, fix the code, and retry once.
- Once you verify the patch, call log_defense to record your success.
"""

@tool
def list_files(directory: str = "") -> str:
    """List all source files in the GrocerGuard codebase. Pass empty string to list from root."""
    return _list_files(directory if directory else None)

@tool
def read_file(path: str) -> str:
    """Read the full content of a file in the codebase."""
    return _read_file(path)

@tool
def search_code(pattern: str, directory: str = "") -> str:
    """Search (grep) for a pattern across .py and .html files."""
    return _search_code(pattern, directory if directory else None)

@tool
def write_file(path: str, content: str) -> str:
    """Write (overwrite) a file in the codebase with new content."""
    return _write_file(path, content)

@tool
def deploy() -> str:
    """Build the modified codebase and deploy it to the grocerguard-redteam Cloud Run service. Returns the service URL or an error message."""
    result = _deploy()
    success = 'failed' not in result.lower()
    try:
        db.log_deploy(success, result)
    except Exception as e:
        logger.warning(f'log_deploy failed: {e}')
    return result

@tool
def http_request(method: str, url: str, body: str = "") -> str:
    """Make an HTTP request to the deployed service or any URL to verify the fix. Set body to empty string if not needed."""
    return str(_http_request(
        method=method,
        url=url,
        body=body if body else None,
        follow_redirects=True,
    ))

@tool
def get_recent_attacks(limit: int = 5) -> str:
    """Fetch recent attacks performed by the red team, including their exploit payloads and target URLs, so you can test if your patch works."""
    return str(db.get_recent_attacks(limit=limit))

@tool
def log_defense(attack_id: str, target_url: str, fixed: bool, evidence: str) -> str:
    """Record the defense result to the database. Set attack_id to empty string if unknown."""
    db.log_defense(
        attack_id=attack_id,
        target_url=target_url,
        fixed=fixed,
        evidence=evidence
    )
    return f"Defense logged for attack_id={attack_id}"


blue_team_agent = Agent(
    name="blue_team",
    model="gemini-3.1-flash",
    instruction=_SYSTEM_BASE,
    tools=[list_files, read_file, search_code, write_file, deploy, http_request, get_recent_attacks, log_defense]
)

def run_agent(instructions: str = '', on_progress=None, on_ask_user=None):
    logger.info('Starting Blue Team Agent (ADK)')

    user_message = 'Please find the recently injected vulnerability, fix it, verify the fix, and log your defense.'
    if instructions:
        user_message += f'\\nAdditional instructions:\\n{instructions}'

    if on_progress:
        on_progress([{'type': 'text', 'text': 'Agent started running...'}])

    # In ADK, you call run() to get the response.
    # We will pass the user_message to the agent.
    # Note: Depending on ADK version, run() may be synchronous and return the final response,
    # or return an iterator. Assuming synchronous for a simple implementation.
    try:
        # Run the agent
        response = blue_team_agent.run(user_message)
        
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Agent finished.\\n\\nFinal response:\\n{response}'}])
            
    except Exception as e:
        logger.exception("Agent run failed")
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Agent failed with error: {e}'}])
