"""Blue team agent — SequentialAgent pipeline: Gather → Analyze → Loop(Patch, Verify) → Refine."""
import os
import logging
import contextvars
from datetime import datetime
from zoneinfo import ZoneInfo

_PST = ZoneInfo('America/Los_Angeles')

# Set in run_agent() per call so per-run tools can find their callbacks.
_ask_user_cv: contextvars.ContextVar = contextvars.ContextVar('ask_user_cb', default=None)
_cwe_progress_cv: contextvars.ContextVar = contextvars.ContextVar('cwe_progress_cb', default=None)
_run_id_cv: contextvars.ContextVar = contextvars.ContextVar('run_id', default=None)

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

def ask_user(question: str) -> str:
    """Ask the human user a short question and return their reply. Use sparingly — only for confirming impactful actions like updating the CWE registry. Returns the user's text reply, or an empty string if no user is connected or no reply within 5 minutes (treat empty reply as 'no')."""
    cb = _ask_user_cv.get()
    if cb is None:
        logger.info('ask_user called but no callback registered — returning empty')
        return ''
    return cb(question)

def update_cwe_plan_notes(cwe_id: str, addition: str) -> str:
    """Append a refinement note to a CWE's plan_notes in the registry. Use only after the user approves."""
    return db.update_cwe_plan_notes(cwe_id, addition)

def update_cwe_code_patterns(cwe_id: str, new_patterns: list[str]) -> str:
    """Add new substring code patterns to a CWE's code_patterns array in the registry. Use only after the user approves."""
    return db.update_cwe_code_patterns(cwe_id, new_patterns)

def mark_cwe_status(cwe_id: str, status: str, note: str = '') -> str:
    """Update live progress for a single CWE candidate so the operator can see how analyze is moving.

    Call this:
      - status='analyzing' when you START investigating a candidate (i.e. before searching its code_patterns).
      - status='confirmed' when you CONFIRM the candidate (Path A or Path B).
      - status='ruled_out' when you decide the candidate is a false positive.

    `note` is a one-line reason (especially useful for ruled_out)."""
    valid = {'analyzing', 'confirmed', 'ruled_out'}
    if status not in valid:
        return f'invalid status — must be one of {sorted(valid)}'
    cb = _cwe_progress_cv.get()
    if cb is None:
        return 'no progress tracker connected'
    cb(cwe_id, status, note)
    return f'marked {cwe_id} as {status}'

def log_defense(attack_id: str, target_url: str, fixed: bool, evidence: str) -> str:
    """Record a defense outcome to the database. Set attack_id to empty string if unknown.
    The current run_id is attached automatically so multiple defenses from one scan group together."""
    run_id = _run_id_cv.get()
    db.log_defense(attack_id=attack_id, target_url=target_url, fixed=fixed,
                   evidence=evidence, run_id=run_id)
    return f"Defense logged for attack_id={attack_id} (run_id={run_id})"


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

Walk through EVERY candidate in the plan, in the order given (priority order). For EACH candidate, decide whether it's confirmed. Collect ALL confirmed vulnerabilities — do NOT stop at the first one. The patch phase will fix all in a single pass.

Each candidate has a boolean `is_planned`:
- is_planned=True  → the registry has code_patterns / plan_notes for this CWE. Run the FULL PLANNED PROTOCOL below (Steps 0-5).
- is_planned=False → the registry knows this CWE exists but has NO plan yet. Run the SHORTER UNPLANNED PROTOCOL further down. The point is to opportunistically seed plans for new CWEs, not to do exhaustive coverage.

═══════ PLANNED PROTOCOL (is_planned=True) ═══════

STEP 0 — mark this candidate as in-progress so the operator sees live status:
   call mark_cwe_status(cwe_id=<this candidate's id>, status='analyzing')
   Do this BEFORE Step 1.

STEP 1 — code-pattern hunt (REQUIRED, deterministic):
   For EACH string in the candidate's `code_patterns` list, call:
     search_code(pattern=<that string>, directory="/tmp/inspections/grocerguard/app")
   Record every file:line that matches. A pattern match is a STRONG, DETERMINISTIC signal — the registry's code_patterns are the ground truth for known vulnerable shapes.
   Zero matches does NOT automatically mean false positive — it just means the plan's known patterns aren't present. Continue to Step 2 anyway; the agent-discovery path below can still confirm a vuln.

STEP 2 — classify findings. There are TWO independent paths to a confirmation; both can fire per candidate.

   PATH A (plan-confirmed) — reserved for Step 1 matches:
     For EACH match from Step 1, read the file in full with read_file. Then check the match against `plan_notes`:
       • If plan_notes describes this pattern's shape as unconditionally vulnerable (e.g. `| safe` rendering user/DB input) → CONFIRMED (plan-confirmed).
       • If plan_notes describes a safe sub-case (e.g. `text(sql)` is safe when used with `:param` binding + a params dict) → check the actual surrounding code for that sub-case. If it's the safe sub-case, false positive. Otherwise CONFIRMED (plan-confirmed).
     plan_notes is authoritative for known shapes. Trust the pattern match — only rule out a match when the plan_notes safe sub-case clearly applies.

   PATH B (agent-discovered) — independent of Step 1:
     Open files in the candidate's `suspect_paths` (and any related route handlers / templates / utility modules) and read them with read_file. The suspect_paths may contain GLOB patterns (e.g. `app/routes/*.py`) — DO NOT pass a glob to read_file. First call list_files on the directory to enumerate the real filenames (e.g. list_files('/tmp/inspections/grocerguard/app/app/routes')), then read each one. Never guess filenames like 'main.py' that you haven't verified exist.
     If you (the model) spot a vulnerability the existing patterns + plan_notes did NOT precisely cover — but you are clearly confident it's exploitable — mark it CONFIRMED (agent-discovered). This path is what catches gaps in the registry and feeds PLAN_REFINEMENT.
     Sub-case: if a Step-1 match also reveals a vulnerability shape DIFFERENT from what plan_notes describes, that additional shape is also agent-discovered.

   A single candidate may produce findings via Path A, Path B, or both. Each finding is one entry in the consolidated list.

STEP 3 — log forensics (REQUIRED):
   For EACH string in the candidate's `log_patterns` list, call:
     search_service_logs("grocerguard", <that pattern>)
   Record any hits.

   In addition to literal pattern matches, you (Gemini) may independently judge a log entry as attack evidence when its shape clearly indicates an attempt at this CWE — even if no `log_patterns` entry matched. Examples: an unusually structured query parameter, a request body containing JS-event handlers, a path with deeply-nested traversal, a POST without a CSRF token from an off-origin Referer, etc. If you see such an entry, treat it as attack evidence the same way as a literal match. (This complements Path B for code: the plan's log_patterns are the deterministic baseline; agent-judged log evidence catches the cases the plan didn't anticipate, and feeds PLAN_REFINEMENT.)

   Either source — literal `log_patterns` hit OR Gemini-judged attack-shaped log entry — counts as "log evidence" for Step 4. Log evidence is significant: it means an attacker has actually exploited (or attempted to exploit) this CWE against the live service. Do not skip this step even if Step 2 already produced a finding.

STEP 4 — decide for this candidate. Combine code findings (Step 2) with log evidence (Step 3):

   Case A — Step 2 found a vulnerability AND Step 3 has matching attack evidence:
     Strongest signal. CONFIRMED — add to list.

   Case B — Step 2 found a vulnerability but Step 3 has no log evidence:
     Real bug, not yet exploited. CONFIRMED — add to list.

   Case C — Step 3 has log evidence but Step 2 found NOTHING (or only matches that look benign per plan_notes):
     A real attack landed but the plan's code_patterns didn't surface it. This is almost certainly an UNPLANNED VULN that the registry's plan needs to learn about. Do NOT give up — re-investigate via Path B:
       * Re-read the suspect files in the candidate's `suspect_paths` (and any related route handlers) looking for vulnerable code shapes the plan didn't anticipate (different ORM helper, a Markup() in a utility module, a sink the plan_notes doesn't mention, etc.).
       * If you spot a real exploitable bug: CONFIRM as agent-discovered AND emit a PLAN_REFINEMENT block seeding the missing code_patterns / plan_notes so future scans catch it deterministically.
       * If after re-reading you genuinely cannot find a code-level bug: still report the log evidence as a finding, with `evidence: "log evidence of past attack at <url/timestamp> but no current vulnerable code found — recommend manual trace"`. Mark Classification as `agent-discovered` and emit a PLAN_REFINEMENT proposing log_patterns refinements + a plan_notes line that flags this as an investigation gap. Don't fabricate a fix target.

   Case D — neither Step 2 nor Step 3 has anything:
     False positive. Skip.

   For any case where you confirm, also require EXPLOITABLE = user input reaches the sink (HTTP route → flow → sink). If the code matches but is unreachable, drop the finding.

STEP 5 — mark final status for this candidate:
   - If at least one finding was confirmed: call mark_cwe_status(cwe_id=<id>, status='confirmed')
   - If false positive / ruled out: call mark_cwe_status(cwe_id=<id>, status='ruled_out', note='<one-line reason>')
   Then move to the next candidate.

═══════ UNPLANNED PROTOCOL (is_planned=False) ═══════

For CWEs without an existing plan, the goal is OPPORTUNISTIC plan-seeding, not full coverage. Spend at most 2-3 tool calls per unplanned CWE.

STEP 0u — mark in-progress:
   call mark_cwe_status(cwe_id=<id>, status='analyzing')

STEP 1u — quick targeted look:
   Use the CWE name (and your own knowledge of how it manifests in a Flask + Spanner web app like GrocerGuard) to pick AT MOST 1-2 files most likely to contain the bug shape, then read them. Examples of quick-look heuristics (use your own judgment, these are not exhaustive):
     - CWE-352 (CSRF): grep route handlers with @<bp>.route(..., methods=['POST'|'PUT'|'DELETE']) for missing CSRFProtect / csrf_token usage.
     - CWE-862 (Missing Authorization): scan admin/* routes for missing @login_required / role checks.
     - CWE-200 (Sensitive Info Exposure): scan responses/templates for password_hash, api_key, secret leaking back to user.
     - CWE-639 (IDOR): scan routes that take an id from request.args/form and look up DB rows without owner-check.
   Do NOT do an exhaustive file-by-file scan; one or two reads is the budget.

STEP 2u — decide:
   - If you spot a clearly exploitable bug AND can articulate a concrete fix: mark CONFIRMED (treat as agent-discovered) AND emit a PLAN_REFINEMENT block in the diagnosis seeding INITIAL code_patterns + plan_notes for this CWE so future scans can detect it deterministically. Then call mark_cwe_status(cwe_id, status='confirmed').
   - Otherwise: call mark_cwe_status(cwe_id=<id>, status='ruled_out', note='unplanned, no obvious vuln spotted in quick read'). Move on.

═══════ AFTER ALL CANDIDATES ═══════

Output the consolidated diagnosis in the format below.

OUTPUT FORMAT:

If at least one CWE was confirmed, output:

CONFIRMED VULNERABILITIES (<count>):

### 1. <CWE-ID> (<name>)
File: <path relative to /tmp/inspections/grocerguard/app/>
Line: <line number>
Vulnerable code:
<the actual snippet>
Attack evidence: <log line showing the attack URL, or "no past attack in logs but code is clearly vulnerable">
Exploit description: <how>
Classification: plan-confirmed | agent-discovered

### 2. <CWE-ID> (<name>)
… same fields …

(continue for every confirmed candidate)

PLAN_REFINEMENTS:

For EACH confirmed candidate that was case (b) — agent-discovered — append one block here. Skip plan-confirmed cases entirely (the existing plan already covers them).

PLAN_REFINEMENT:
cwe_id: <CWE-ID>
new_code_patterns: <JSON list of substring patterns the plan was missing — may be []>
new_plan_notes_addition: <one short paragraph of guidance to APPEND to plan_notes — may be empty>
reasoning: <one sentence: why the plan was insufficient>

If NO CWE was confirmed, output:

NO CONFIRMED VULNERABILITIES — all candidates checked. <one-line summary per candidate of why ruled out>
"""

_PATCH_INSTRUCTION = f"""
You are the Patch phase of an automated blue team security pipeline for GrocerGuard.

Diagnosis from the Analyze phase (may contain MULTIPLE confirmed vulnerabilities):
{{diagnosis}}

Each vulnerability points to a file in /tmp/inspections/grocerguard/app/<path>. Apply every fix in the deployable codebase at {CODEBASE_DIR}/<path> — that directory has the Dockerfile and is what gets built and deployed.

Procedure:

1. For EACH confirmed vulnerability in the diagnosis (in order):
   a. Call read_file({CODEBASE_DIR}/<path>) to read the current file contents.
   b. Call write_file({CODEBASE_DIR}/<path>, <new contents>) to apply a minimal, surgical fix — change as few lines as possible. Keep all unrelated code intact.
   c. If the same file appears in multiple vulnerabilities, fix them all in a SINGLE write_file call (read once, apply all edits, write once) to avoid clobbering earlier fixes.

2. After ALL fixes are written, call deploy() ONCE. A single deploy ships every fix together — do NOT call deploy() multiple times in this turn.

3. If deploy() fails, examine the error, repair the code (read_file + write_file as needed), and call deploy() ONE more time. Do NOT exceed two total deploy calls.

If the diagnosis says "NO CONFIRMED VULNERABILITIES", emit a one-line "no patches to apply" message and end your turn — do not call any tools.
"""

_VERIFY_INSTRUCTION = """
You are the Verify phase of an automated blue team security pipeline for GrocerGuard.

Diagnosis that was patched (may contain MULTIPLE confirmed vulnerabilities):
{diagnosis}

Your job is to confirm EVERY patch works using the red team's actual attack data. This is the first phase with access to red team intel.

Procedure:

1. Call get_recent_attacks(20) to get the red team's recent payloads and target URLs (one or more per CWE).

2. For EACH vulnerability in the diagnosis, find the matching attack(s) in get_recent_attacks output by cwe_id. Replay each payload against the live service using http_request.

3. For each replayed attack, classify the response and decide:

   a. RESPONSE 5xx (500, 502, 503, 504, etc.): This is NOT proof the attack was blocked — the target is probably mid-deploy, unhealthy, or briefly unreachable. NEVER call log_defense(fixed=True) on a 5xx response.
      Retry the same payload ONCE (a fresh http_request call). If the retry also returns 5xx, mark this attack as INCONCLUSIVE: call log_defense(attack_id, target_url, fixed=False, evidence='inconclusive: target returned 5xx on both attempts — service likely deploying or unhealthy') and treat the CWE as still-broken so the loop retries.

   b. RESPONSE 2xx/3xx and attack payload is reflected / injection still works (e.g. UNION query results visible, <script> tag present in response body, /etc/passwd contents leaked): the attack still succeeds. log_defense(fixed=False, evidence=<short still-exploitable snippet>) and treat as still-broken.

   c. RESPONSE 2xx/3xx and attack payload is neutralized (escaped, not reflected, returns benign output): the patch worked. log_defense(fixed=True, evidence=<short blocked-response snippet>).

   d. RESPONSE 4xx (400, 403, 404): the route rejected the request. This is usually a valid fix signal IF the rejection appears defense-driven (input validation, auth check). Use judgment — a generic 404 across the whole site (not just for malicious input) is suspicious; the patch may have accidentally broken the route. When in doubt, retry with a benign payload to confirm the route is still alive, then log_defense(fixed=True) only if the malicious payload is rejected while benign requests succeed.

4. If no recent attacks exist for a confirmed CWE, treat it as untestable — note this in your output and consider it FIXED (we patched the code; we just have no replay payload yet).

5. Decide:
   - If EVERY confirmed vulnerability was either neutralized (fixed=True) or untestable (no payload): call exit_loop. Pipeline complete.
   - If ANY vulnerability is still exploitable OR inconclusive: do NOT call exit_loop. Output a clear list of what's still broken (and any inconclusive ones) so the patch phase can iterate. The loop will re-run patch then verify.

If the diagnosis says "NO CONFIRMED VULNERABILITIES", emit "nothing to verify" and call exit_loop immediately.
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
    tools=[list_files, read_file, search_code, search_service_logs, mark_cwe_status],
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

_REFINE_INSTRUCTION = """
You are the Refine phase. You run after the patch/verify loop completes.

The diagnosis from the Analyze phase is:

{diagnosis}

Your purpose: when Analyze flagged "agent-discovered" vulnerabilities (i.e. the existing CWE plans didn't precisely cover them), propose plan updates to the user one CWE at a time. The diagnosis may contain ZERO, ONE, or MORE `PLAN_REFINEMENT:` blocks — handle each independently.

GATING RULE: scan the diagnosis above. If it does NOT contain the literal marker "PLAN_REFINEMENT:", emit "no refinement needed" and END YOUR TURN. Do not call any tools. The plans were already sufficient.

If the diagnosis DOES contain at least one PLAN_REFINEMENT:, do this:

1. Open with a 4-bullet summary of the entire exercise:
   - CWEs confirmed (count + list)
   - Files/lines patched
   - Verify outcome (all neutralized? any still broken?)
   - Number of plan-refinement candidates to review below

2. For EACH PLAN_REFINEMENT block (in the order they appear), do all of this in sequence. Each iteration MUST issue an ask_user TOOL CALL — not just print the prompt as text. The user only sees a Yes/No button when ask_user is actually invoked as a tool.

   a. Parse the block to extract: cwe_id, new_code_patterns (JSON list), new_plan_notes_addition (string), reasoning (one sentence).

   b. INVOKE the `ask_user` TOOL (do not print this as text). Pass a single-string `question` argument that summarizes the proposed update for THIS one CWE. Example shape (yours can be different in wording, but keep it short and end with "Reply yes/no."):

       ask_user(question="Refine CWE-79 plan?\n• Add code_patterns: ['innerHTML =']\n• Append note: 'React-style innerHTML assignment with user data is XSS.'\nReply yes/no.")

      The tool will block until the user clicks Yes / No / replies. Its return value is the user's reply string (or empty string on timeout).

   c. Read the tool's return value:
      - If the reply starts with 'y' (case-insensitive — yes/Yes/yep/yeah): apply the updates for THIS CWE by INVOKING the relevant update tools.
          * If new_code_patterns is non-empty: INVOKE update_cwe_code_patterns(cwe_id, new_code_patterns).
          * If new_plan_notes_addition is non-empty: INVOKE update_cwe_plan_notes(cwe_id, new_plan_notes_addition).
          * Briefly summarize each tool's return value as text afterward.
      - Otherwise (empty / 'n' / 'no' / anything else): output ONE LINE "skipping CWE-X refinement" as text and move to the next block.

   d. Continue to the next PLAN_REFINEMENT block. Each block needs its own ask_user invocation.

CRITICAL: never print "Refine CWE-X plan? … Reply yes/no." as plain text. That is what `ask_user` is for. If you print it as text, the user sees no input controls and the refinement is lost.

3. After all blocks are processed, end your turn.

Keep total output under 500 words across all blocks. Be concise per CWE.
"""

refine_agent = Agent(
    name="refine",
    model=_model(),
    instruction=_REFINE_INSTRUCTION,
    tools=[ask_user, update_cwe_plan_notes, update_cwe_code_patterns],
    before_model_callback=_before_model,
    after_model_callback=_after_model,
)

blue_team_agent = SequentialAgent(
    name="blue_team",
    sub_agents=[gather_agent, analyze_agent, patch_verify_loop, refine_agent],
)


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_agent(instructions: str = '', on_progress=None, on_ask_user=None, on_state=None, on_cwe_progress=None, run_id=None):
    """Run the pipeline.
    - on_state(key, value): called when an agent's output_key is written (gather_findings, diagnosis).
    - on_cwe_progress(cwe_id, status, note): called when analyze marks a candidate's status.
    - run_id: tagged onto defense_log entries so multi-CWE scans group together on the leaderboard."""
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
            # Register per-run callbacks so the corresponding tools can find them.
            cv_token = _ask_user_cv.set(on_ask_user) if on_ask_user else None
            cv_token_progress = _cwe_progress_cv.set(on_cwe_progress) if on_cwe_progress else None
            cv_token_runid = _run_id_cv.set(run_id) if run_id else None
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
                            'text': part.text[:2000],
                        }
                        if on_progress:
                            on_progress(_stamp([step]))

                # After each event, surface any newly written output_keys.
                if on_state and event.actions and event.actions.state_delta:
                    for k, v in event.actions.state_delta.items():
                        if isinstance(v, str):
                            on_state(k, v)
            if cv_token is not None:
                _ask_user_cv.reset(cv_token)
            if cv_token_progress is not None:
                _cwe_progress_cv.reset(cv_token_progress)
            if cv_token_runid is not None:
                _run_id_cv.reset(cv_token_runid)
            return reply

        reply = asyncio.run(_run())

        logger.info('Blue team pipeline complete')
        if on_progress and reply:
            on_progress(_stamp([{'type': 'text', 'text': f'Pipeline complete.\n\n{reply}'}]))

    except Exception as e:
        logger.exception("Agent pipeline failed")
        if on_progress:
            on_progress([{'type': 'text', 'text': f'Pipeline failed: {e}'}])
