"""Claude Opus 4.7 red team agent with tool use agentic loop."""
import logging
import anthropic
import db
from tools.codebase import list_files, read_file, write_file, search_code
from tools.deploy import deploy
from tools.http_client import http_request

logger = logging.getLogger(__name__)

client = anthropic.Anthropic()

SYSTEM = """You are an automated red team security agent for GrocerGuard, a Flask/Cloud Spanner grocery web app.

Your mission each run:
1. You will be given a CWE (Common Weakness Enumeration) to exploit.
2. Read the GrocerGuard codebase to understand the relevant code paths.
3. Inject a realistic, exploitable vulnerability matching the CWE into the codebase.
4. Deploy the modified codebase to the grocerguard-redteam Cloud Run service.
5. Attack the live service to confirm the vulnerability is exploitable.
6. Log your findings with clear evidence.

Guidelines:
- Make surgical changes — modify as few files as needed to introduce the vulnerability.
- The vulnerability must be realistically exploitable via HTTP (not theoretical).
- After deploying, confirm exploitation with actual HTTP requests to the service.
- Be specific in your evidence: include request payloads, response bodies, and what was leaked/achieved.
- If deployment fails, read the error, fix the code, and retry once.
- If the attack does not confirm the vulnerability after 3 attempts, log status=unconfirmed and stop.

You have access to the following tools:
- list_files: list all source files in the codebase
- read_file: read a file's content
- search_code: grep for a pattern across the codebase
- write_file: write/overwrite a file with new content
- deploy: build and deploy the modified codebase to grocerguard-redteam
- http_request: make HTTP requests to the deployed service
- log_finding: record the attack result to the database
"""

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
            'Build the modified codebase and deploy it to the grocerguard-redteam '
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


def dispatch_tool(name, inputs):
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
        return deploy()
    if name == 'http_request':
        return str(http_request(
            method=inputs['method'],
            url=inputs['url'],
            headers=inputs.get('headers'),
            body=inputs.get('body'),
            cookies=inputs.get('cookies'),
            follow_redirects=inputs.get('follow_redirects', True),
        ))
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


def run_agent(cwe_id, cwe_name, cwe_score, instructions=''):
    logger.info(f'Starting red team agent for {cwe_id}: {cwe_name} (score={cwe_score})')

    user_message = (
        f'Your target vulnerability for this run:\n'
        f'  CWE ID:   {cwe_id}\n'
        f'  Name:     {cwe_name}\n'
        f'  Score:    {cwe_score}\n\n'
        f'Begin by exploring the codebase to find the best injection point. '
        f'Then inject the vulnerability, deploy, attack, and log your findings.'
    )

    if instructions:
        user_message += f'\n\nAdditional instructions:\n{instructions}'

    messages = [{'role': 'user', 'content': user_message}]

    while True:
        response = client.messages.create(
            model='claude-opus-4-7',
            max_tokens=8096,
            thinking={'type': 'adaptive'},
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
        )
        logger.info(f'Claude stop_reason={response.stop_reason}')

        # Append assistant turn
        messages.append({'role': 'assistant', 'content': response.content})

        if response.stop_reason == 'end_turn':
            logger.info('Agent finished.')
            break

        if response.stop_reason != 'tool_use':
            logger.warning(f'Unexpected stop_reason: {response.stop_reason}')
            break

        # Execute all tool calls and collect results
        tool_results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue
            result = dispatch_tool(block.name, block.input)
            tool_results.append({
                'type': 'tool_result',
                'tool_use_id': block.id,
                'content': str(result),
            })

        messages.append({'role': 'user', 'content': tool_results})
