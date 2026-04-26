"""File system tools for reading and modifying the GrocerGuard codebase."""
import os
import subprocess

CODEBASE_DIR = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')

_SKIP_DIRS = {'__pycache__', '.git', '.venv', 'venv', 'node_modules', 'instance'}
_INCLUDE_EXT = {'.py', '.html', '.css', '.js', '.txt', '.ddl', '.yaml', '.yml'}


def list_files(directory=None):
    base = directory or CODEBASE_DIR
    result = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1] in _INCLUDE_EXT:
                result.append(os.path.join(root, f))
    return '\n'.join(result) if result else '(no files found)'


def read_file(path):
    # Resolve relative paths against CODEBASE_DIR
    if not os.path.isabs(path):
        path = os.path.join(CODEBASE_DIR, path)
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def write_file(path, content):
    # Resolve relative paths against CODEBASE_DIR
    if not os.path.isabs(path):
        path = os.path.join(CODEBASE_DIR, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return f'Written {len(content)} bytes to {path}'


def search_code(pattern, directory=None):
    base = directory or CODEBASE_DIR
    result = subprocess.run(
        ['grep', '-rn', '--include=*.py', '--include=*.html', pattern, base],
        capture_output=True, text=True
    )
    output = result.stdout.strip()
    return output if output else '(no matches)'
