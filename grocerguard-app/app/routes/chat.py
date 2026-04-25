"""Red team chatbot — Claude-powered interface to the red-team-agent service."""
import os
import json
import requests as http
import anthropic
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

chat = Blueprint('chat', __name__)

_anthropic = anthropic.Anthropic()

AGENT_URL = os.environ.get('REDTEAM_AGENT_URL', '')

SYSTEM = """You are the GrocerGuard Security Operations assistant.
You help security engineers manage the automated red team agent that injects and tests vulnerabilities in the GrocerGuard application.

You have two tools:
- start_attack: trigger a red team run (inject a vuln, attack it, or both)
- get_status: check the status of recent runs

When the user asks you to start an attack, use start_attack. Be specific about which mode and CWE makes sense from context.
When the user asks about status or results, use get_status.
For anything else (questions, explanations), answer directly without using tools.

Keep responses concise and use plain text — no markdown headers, minimal bullet points."""

TOOLS = [
    {
        'name': 'start_attack',
        'description': 'Trigger a red team attack run against the target GrocerGuard service.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'mode': {
                    'type': 'string',
                    'enum': ['inject', 'attack', 'both'],
                    'description': 'inject=only modify code+deploy, attack=only attack existing vuln, both=full pipeline',
                },
                'cwe_id': {
                    'type': 'string',
                    'description': 'Optional CWE to target (e.g. CWE-79). Omit to auto-select.',
                },
                'instructions': {
                    'type': 'string',
                    'description': 'Specific instructions for the agent, e.g. which endpoint to target.',
                },
            },
            'required': ['mode'],
        },
    },
    {
        'name': 'get_status',
        'description': 'Get status of recent attack runs, or a specific run by ID.',
        'input_schema': {
            'type': 'object',
            'properties': {
                'run_id': {
                    'type': 'string',
                    'description': 'Optional run ID for a specific run. Omit to list all recent runs.',
                },
            },
            'required': [],
        },
    },
]


def _call_agent(tool_name, tool_input):
    if not AGENT_URL:
        return {'error': 'REDTEAM_AGENT_URL is not configured'}
    try:
        if tool_name == 'start_attack':
            resp = http.post(f'{AGENT_URL}/run', json=tool_input, timeout=30)
            return resp.json()
        elif tool_name == 'get_status':
            run_id = tool_input.get('run_id', '').strip()
            url = f'{AGENT_URL}/runs/{run_id}' if run_id else f'{AGENT_URL}/runs'
            resp = http.get(url, timeout=10)
            return resp.json()
    except Exception as e:
        return {'error': str(e)}


@chat.route('/chat')
@login_required
def index():
    if not current_user.is_admin:
        return render_template('errors/403.html'), 403
    return render_template('chat.html')


@chat.route('/chat/message', methods=['POST'])
@login_required
def message():
    if not current_user.is_admin:
        return jsonify({'error': 'forbidden'}), 403

    data     = request.get_json(silent=True) or {}
    history  = data.get('history', [])   # [{role, content}] from client
    user_msg = data.get('message', '').strip()
    if not user_msg:
        return jsonify({'error': 'empty message'}), 400

    messages = history + [{'role': 'user', 'content': user_msg}]

    # Agentic loop — Claude may call tools before giving a final answer
    while True:
        response = _anthropic.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=1024,
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
        )

        messages.append({'role': 'assistant', 'content': response.content})

        if response.stop_reason == 'end_turn':
            text = next(
                (b.text for b in response.content if hasattr(b, 'text')),
                '(no response)'
            )
            return jsonify({'reply': text, 'history': messages})

        if response.stop_reason != 'tool_use':
            break

        tool_results = []
        for block in response.content:
            if block.type != 'tool_use':
                continue
            result = _call_agent(block.name, block.input)
            tool_results.append({
                'type':        'tool_result',
                'tool_use_id': block.id,
                'content':     json.dumps(result),
            })
        messages.append({'role': 'user', 'content': tool_results})

    return jsonify({'reply': 'Something went wrong — try again.', 'history': messages})
