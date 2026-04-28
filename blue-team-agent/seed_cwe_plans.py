"""Seed/update CWE plans in cwe_registry. Idempotent — only writes the 4 plan columns;
leaves cwe_id/name/rank/score alone (red-team-agent maintains those)."""
import os
from google.cloud import spanner

os.environ.setdefault('SPANNER_PROJECT_ID', 'zhiting-personal')
os.environ.setdefault('SPANNER_INSTANCE_ID', 'grocerguard-instance')
os.environ.setdefault('SPANNER_DATABASE_ID', 'grocerguard')

# (cwe_id, suspect_paths, code_patterns, log_patterns, plan_notes)
PLANS = [
    ('CWE-89',
     ['app/routes/*.py', 'app/models.py'],
     ['text(', 'execute_sql', 'execute_update', 'db.session.execute',
      '+ request.', 'f"SELECT', "f'SELECT", '.format(', '% search'],
     ['UNION', ' OR 1', '%27', '--', "' OR ", 'SELECT FROM'],
     'Parameterized `text(sql)` with `:param` placeholders bound through a params '
     'dict is SAFE — only flag string concatenation, f-strings, %-format, or .format() '
     'that mixes user input directly into the SQL string.'),

    ('CWE-79',
     ['app/templates/**/*.html', 'app/routes/*.py'],
     ['|safe', 'Markup(', 'autoescape false', 'render_template_string'],
     ['<script', 'javascript:', 'onerror=', '%3Cscript', '<img '],
     'Jinja2 autoescapes by default; `|safe` or `Markup()` opts out. Reflected XSS '
     'is unescaped user input rendered in templates; stored XSS is unescaped DB '
     'content rendered the same way.'),

    ('CWE-78',
     ['app/routes/*.py', 'app/utils/*.py'],
     ['os.system(', 'subprocess.', 'shell=True', 'os.popen('],
     ['; ls', '; rm ', '&& ', '$( ', ';cat '],
     '`subprocess.run([...])` with a list and `shell=False` is SAFE. `shell=True` '
     'or `os.system()` with concatenated user input is the bug.'),

    ('CWE-22',
     ['app/routes/*.py', 'app/gcs.py'],
     ['open(', 'send_file(', "request.args.get('file", "request.args.get('path"],
     ['../', '..%2F', '%2e%2e', '/etc/passwd', '/etc/shadow'],
     'User-supplied filename joined into a path without validation. '
     '`os.path.realpath` + prefix check is the safe pattern.'),

    ('CWE-94',
     ['app/routes/*.py', 'app/utils/*.py'],
     ['eval(', 'exec(', 'compile(', 'pickle.loads', 'yaml.load('],
     ['eval(', 'exec(', '__import__'],
     '`yaml.load()` without `Loader=SafeLoader` is unsafe. `pickle.loads` of '
     'untrusted data executes arbitrary code.'),
]


def main():
    project  = os.environ['SPANNER_PROJECT_ID']
    instance = os.environ['SPANNER_INSTANCE_ID']
    database = os.environ['SPANNER_DATABASE_ID']

    client = spanner.Client(project=project)
    db = client.instance(instance).database(database)

    rows = [(cwe_id, suspect_paths, code_patterns, log_patterns, plan_notes)
            for (cwe_id, suspect_paths, code_patterns, log_patterns, plan_notes) in PLANS]

    with db.batch() as batch:
        batch.update(
            table='cwe_registry',
            columns=['cwe_id', 'suspect_paths', 'code_patterns', 'log_patterns', 'plan_notes'],
            values=rows,
        )

    print(f'Updated plans for {len(rows)} CWEs:')
    for cwe_id, *_ in PLANS:
        print(f'  {cwe_id}')


if __name__ == '__main__':
    main()
