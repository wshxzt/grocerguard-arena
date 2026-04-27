"""Claude Opus 4.7 red team agent with tool use agentic loop."""
import logging
import anthropic
import db
from tools.codebase import list_files, read_file, write_file, search_code
from tools.deploy import deploy
from tools.http_client import http_request

logger = logging.getLogger(__name__)

client = anthropic.Anthropic()

_SYSTEM_BASE = """You are an automated red team security agent for GrocerGuard, a Flask/Cloud Spanner grocery web app.

Guidelines:
- Make surgical changes — modify as few files as needed to introduce the vulnerability.
- The vulnerability must be realistically exploitable via HTTP (not theoretical).
- After deploying, confirm exploitation with actual HTTP requests to the service.
- Be specific in your evidence: include request payloads, response bodies, and what was leaked/achieved.
- If deployment fails, read the error, fix the code, and retry once.
- If you are stuck after retrying (repeated deploy failures, ambiguous results, missing information), call ask_user to pause and get human guidance rather than giving up.
- If the attack does not confirm the vulnerability after 3 attempts, call ask_user before logging status=unconfirmed.
"""

_MODE_INSTRUCTIONS = {
    'inject': (
        'Mode: inject only.\n'
        'Explore the codebase, inject the vulnerability, and deploy. '
        'Do NOT perform any HTTP attacks after deployment. '
        'Log your finding with status=confirmed and evidence describing what you injected and where.'
    ),
    'attack': (
        'Mode: attack only.\n'
        'The grocerguard service already has a vulnerability deployed — do NOT touch the codebase. '
        'Skip list_files, read_file, write_file, search_code, and deploy. '
        'Go straight to attacking the live service with http_request, then log your findings.'
    ),
    'both': (
        'Mode: full pipeline.\n'
        'Explore the codebase, inject the vulnerability, deploy, attack the live service, and log your findings.'
    ),
}

TOOLS = [
    {
        'name': 'list_files',
        'description': 'List all source files in the GrocerGuard codebase.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'directory': {
                    'type': 'string',
                    'description': 'Optional subdirectory to list. Defaults to the full codebase.',
                },
            },
            'required': [],
        },
    },
    {
        'name': 'read_file',
        'description': 'Read the full content of a file in the codebase.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string', 'description': 'Absolute path to the file.'},
            },
            'required': ['path'],
        },
    },
    {
        'name': 'search_code',
        'description': 'Search (grep) for a pattern across .py and .html files.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'pattern': {'type': 'string', 'description': 'Regex or literal string to search for.'},
                'directory': {'type': 'string', 'description': 'Optional subdirectory to search within.'},
            },
            'required': ['pattern'],
        },
    },
    {
        'name': 'write_file',
        'description': 'Write (overwrite) a file in the codebase with new content.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string', 'description': 'Absolute path to the file.'},
                'content': {'type': 'string', 'description': 'Full new content of the file.'},
            },
            'required': ['path', 'content'],
        },
    },
    {
        'name': 'deploy',
        'description': (
            'Build the modified codebase and deploy it to the grocerguard '
            'Cloud Run service. Returns the service URL or an error message.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {},
            'required': [],
        },
    },
    {
        'name': 'http_request',
        'description': 'Make an HTTP request to the deployed service or any URL.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'method': {'type': 'string', 'description': 'HTTP method: GET, POST, PUT, DELETE, etc.'},
                'url': {'type': 'string', 'description': 'Full URL to request.'},
                'headers': {
                    'type': 'object',
                    'description': 'Optional HTTP headers as a key-value map.',
                    'additionalProperties': {'type': 'string'},
                },
                'body': {
                    'type': 'string',
                    'description': 'Optional request body (raw string or URL-encoded form data).',
                },
                'cookies': {
                    'type': 'object',
                    'description': 'Optional cookies as a key-value map.',
                    'additionalProperties': {'type': 'string'},
                },
                'follow_redirects': {
                    'type': 'boolean',
                    'description': 'Whether to follow HTTP redirects. Default true.',
                },
            },
            'required': ['method', 'url'],
        },
    },
    {
        'name': 'ask_user',
        'description': (
            'Pause the run and ask the human operator a question. '
            'Use when you are blocked and cannot proceed without guidance — '
            'e.g. repeated deploy failures, ambiguous vulnerability location, or attack not working after retries.'
        ),
        'input_schema': {
            'type': 'object',
            'properties': {
                'question': {'type': 'string', 'description': 'The question to ask the operator.'},
            },
            'required': ['question'],
        },
    },
    {
        'name': 'log_finding',
        'description': 'Record the attack result to the database.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'cwe_id': {'type': 'string', 'description': 'CWE identifier, e.g. CWE-89.'},
                'target_url': {'type': 'string', 'description': 'URL that was attacked.'},
                'payload': {'type': 'string', 'description': 'Attack payload used.'},
                'status': {
                    'type': 'string',
                    'enum': ['confirmed', 'unconfirmed', 'failed'],
                    'description': 'Result of the attack attempt.',
                },
                'evidence': {'type': 'string', 'description': 'Evidence of exploitation (response body, leaked data, etc.).'},
            },
            'required': ['cwe_id', 'status', 'evidence'],
        },
    },
]


def _summarize_inputs(name, inputs):
    """Compact display of tool inputs — omit large payloads."""
    if name == 'write_file':
        return {'path': inputs.get('path', ''), 'content': '[...]'}
    if name == 'http_request':
        return {'method': inputs.get('method', ''), 'url': inputs.get('url', '')}
    if name == 'log_finding':
        return {'cwe_id': inputs.get('cwe_id', ''), 'status': inputs.get('status', '')}
    return {k: str(v)[:120] for k, v in inputs.items()}


def dispatch_tool(name, inputs, cwe_id=None, on_ask_user=None):
    logger.info(f'Tool call: {name}({list(inputs.keys())})')
    if name == 'list_files':
        return list_files(inputs.get('directory'))
    if name == 'read_file':
        return read_file(inputs['path'])
    if name == 'search_code':
        return search_code(inputs['pattern'], inputs.get('directory'))
    if name == 'write_file':
        return write_file(inputs['path'], inputs['content'])
    if name == 'deploy':
        result = deploy()
        success = 'failed' not in result.lower()
        try:
            db.log_deploy(cwe_id or '', success, result)
        except Exception as e:
            logger.warning(f'log_deploy failed: {e}')
        return result
    if name == 'http_request':
        return str(http_request(
            method=inputs['method'],
            url=inputs['url'],
            headers=inputs.get('headers'),
            body=inputs.get('body'),
            cookies=inputs.get('cookies'),
            follow_redirects=inputs.get('follow_redirects', True),
        ))
    if name == 'ask_user':
        question = inputs.get('question', '')
        if on_ask_user:
            return on_ask_user(question)
        return 'No operator available — continue with your best judgment.'
    if name == 'log_finding':
        db.log_finding(
            cwe_id=inputs['cwe_id'],
            target_url=inputs.get('target_url', ''),
            payload=inputs.get('payload', ''),
            status=inputs['status'],
            evidence=inputs['evidence'],
        )
        return f"Finding logged: {inputs['cwe_id']} — {inputs['status']}"
    return f'Unknown tool: {name}'


def run_agent(cwe_id, cwe_name, cwe_score, mode='both', instructions='', on_progress=None, on_ask_user=None):
    logger.info(f'Starting agent: {cwe_id} ({cwe_name}), mode={mode}')

    mode = mode if mode in _MODE_INSTRUCTIONS else 'both'
    system = _SYSTEM_BASE + '\n' + _MODE_INSTRUCTIONS[mode]

    user_message = (
        f'Target vulnerability:\n'
        f'  CWE ID:   {cwe_id}\n'
        f'  Name:     {cwe_name}\n'
        f'  Score:    {cwe_score}\n'
    )
    if instructions:
        user_message += f'\nAdditional instructions:\n{instructions}'

    messages = [{'role': 'user', 'content': user_message}]

    while True:
        response = client.messages.create(
            model='claude-opus-4-7',
            max_tokens=8096,
            thinking={'type': 'adaptive', 'display': 'summarized'},
            system=system,
            tools=TOOLS,
            messages=messages,
        )
        logger.info(f'Claude stop_reason={response.stop_reason}')

        # Emit progress: thinking summaries, text, and tool calls from this turn
        if on_progress:
            steps = []
            for block in response.content:
                if block.type == 'thinking' and getattr(block, 'thinking', ''):
                    steps.append({'type': 'thinking', 'text': block.thinking[:500]})
                elif block.type == 'text' and getattr(block, 'text', ''):
                    steps.append({'type': 'text', 'text': block.text[:300]})
                elif block.type == 'tool_use':
                    steps.append({
                        'type': 'tool_call',
                        'tool': block.name,
                        'inputs': _summarize_inputs(block.name, block.input),
                    })
            if steps:
                on_progress(steps)

        messages.append({'role': 'assistant', 'content': response.content})

        if response.stop_reason == 'end_turn':
            logger.info('Agent finished.')
            if on_progress:
                try:
                    summary_resp = client.messages.create(
                        model='claude-haiku-4-5',
                        max_tokens=600,
                        system=(
                            'Summarize this red team operation in 4-6 concise bullet points for the operator. '
                            'Cover: vulnerability targeted, code change made, deploy outcome, '
                            'attack result, and final logged status. Be specific — include filenames, '
                            'payloads, and evidence snippets where available. No markdown headers.'
                        ),
                        messages=messages + [{'role': 'user', 'content': 'Summarize the operation above.'}],
                    )
                    summary = next((b.text for b in summary_resp.content if hasattr(b, 'text')), '')
                    if summary:
                        on_progress([{'type': 'text', 'text': f'📋 Operation summary:\n{summary}'}])
                except Exception as e:
                    logger.warning(f'Summary generation failed: {e}')
            break

        if response.stop_reason != 'tool_use':
            logger.warning(f'Unexpected stop_reason: {response.stop_reason}')
            break

        tool_results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue
            result = dispatch_tool(block.name, block.input, cwe_id=cwe_id, on_ask_user=on_ask_user)
            tool_results.append({
                'type': 'tool_result',
                'tool_use_id': block.id,
                'content': str(result),
            })
            if block.name == 'deploy' and on_progress:
                success = 'failed' not in str(result).lower() and 'error' not in str(result).lower()
                icon = '✅' if success else '❌'
                on_progress([{'type': 'text', 'text': f'{icon} Deploy result: {str(result)[:300]}'}])

        messages.append({'role': 'user', 'content': tool_results})
