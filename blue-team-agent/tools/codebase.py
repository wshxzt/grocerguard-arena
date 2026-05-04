"""File system tools for reading and modifying the GrocerGuard codebase."""
import os
import difflib
import subprocess
import logging

logger = logging.getLogger(__name__)

CODEBASE_DIR = os.environ.get('CODEBASE_DIR', '/workspace/grocerguard-arena/grocerguard-app')

_SKIP_DIRS = {'__pycache__', '.git', '.venv', 'venv', 'node_modules', 'instance'}
_INCLUDE_EXT = {'.py', '.html', '.css', '.js', '.txt', '.ddl', '.yaml', '.yml'}


def list_files(directory=None):
    base = directory or CODEBASE_DIR
    if not os.path.isdir(base):
        # Try to be helpful: list the closest existing ancestor.
        parent = base
        while parent and parent != '/' and not os.path.isdir(parent):
            parent = os.path.dirname(parent)
        hint = f' Closest existing dir: {parent}' if parent else ''
        return f'(directory not found: {base}.{hint})'
    result = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1] in _INCLUDE_EXT:
                result.append(os.path.join(root, f))
    return '\n'.join(result) if result else '(no files found)'


def read_file(path):
    # Resolve relative paths against CODEBASE_DIR
    orig = path
    if not os.path.isabs(path):
        path = os.path.join(CODEBASE_DIR, path)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        # Help the agent recover: list siblings in the parent dir if it exists.
        parent = os.path.dirname(path)
        if os.path.isdir(parent):
            try:
                siblings = [n for n in os.listdir(parent) if not n.startswith('.')]
            except OSError:
                siblings = []
            return (f'(file not found: {orig}. Parent dir {parent} exists; '
                    f'contents: {sorted(siblings)[:30]}. Use list_files for full enumeration.)')
        return f'(file not found: {orig}. Parent dir {parent} does not exist either.)'
    except IsADirectoryError:
        return f'(path is a directory, not a file: {orig}. Use list_files instead.)'
    except OSError as e:
        return f'(read_file error on {orig}: {e})'


def write_file(path, content):
    orig = path
    if not os.path.isabs(path):
        path = os.path.join(CODEBASE_DIR, path)

    before = ''
    try:
        with open(path, 'r', encoding='utf-8') as f:
            before = f.read()
    except (FileNotFoundError, UnicodeDecodeError, OSError):
        before = ''

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    except OSError as e:
        logger.warning(f'write_file failed on {path}: {e}')
        return f'(write_file error on {orig}: {e})'
    logger.info(f'write_file: {path} ({len(content)} bytes)')

    # Persist a patch_log entry so the leaderboard can show before/after
    # diffs per run. Best-effort: a logging failure must not break the run.
    try:
        import db
        from agent import _run_id_cv
        run_id = _run_id_cv.get()
        rel = os.path.relpath(path, CODEBASE_DIR) if path.startswith(CODEBASE_DIR) else path
        diff = ''.join(difflib.unified_diff(
            before.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f'a/{rel}',
            tofile=f'b/{rel}',
            n=3,
        ))
        db.log_patch(run_id=run_id, file_path=rel, unified_diff=diff,
                     bytes_before=len(before), bytes_after=len(content))
    except Exception as e:
        logger.warning(f'log_patch failed (non-fatal): {e}')

    return f'Written {len(content)} bytes to {path}'


def search_code(pattern, directory=None):
    base = directory or CODEBASE_DIR
    # -F: fixed string (no regex). Substring match — the LLM rarely wants regex
    # and over-escapes special chars when it does, breaking the search.
    result = subprocess.run(
        ['grep', '-rnF', '--include=*.py', '--include=*.html', pattern, base],
        capture_output=True, text=True
    )
    output = result.stdout.strip()
    matches = len(output.splitlines()) if output else 0
    logger.info(f'search_code: pattern={pattern!r} in {base} → {matches} match(es)')
    return output if output else '(no matches)'
