"""GrocerGuard Arena Leaderboard."""
import os
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import requests as http
from flask import Flask, render_template, abort
from google.cloud import spanner

logger = logging.getLogger(__name__)

AGENT_URL     = os.environ.get('AGENT_URL',      'https://red-team-agent-929315648024.us-central1.run.app')
BLUE_TEAM_URL = os.environ.get('BLUE_TEAM_URL', 'https://blue-team-agent-929315648024.us-central1.run.app')

app = Flask(__name__)

_PST = ZoneInfo('America/Los_Angeles')

@app.template_filter('pst')
def to_pst(dt):
    if dt is None:
        return '—'
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except Exception:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_PST).strftime('%Y-%m-%d %H:%M')

PROJECT  = os.environ['SPANNER_PROJECT_ID']
INSTANCE = os.environ['SPANNER_INSTANCE_ID']
DATABASE = os.environ.get('SPANNER_DATABASE_ID', 'grocerguard')

_db = None


def get_db():
    global _db
    if _db is None:
        client   = spanner.Client(project=PROJECT)
        instance = client.instance(INSTANCE)
        _db      = instance.database(DATABASE)
    return _db


def fetch_stats():
    with get_db().snapshot() as snap:
        row = snap.execute_sql(
            """SELECT
                 COUNT(*)                          AS total,
                 COUNTIF(status = 'confirmed')     AS confirmed,
                 COUNTIF(status = 'unconfirmed')   AS unconfirmed,
                 COUNTIF(status = 'failed')        AS failed
               FROM attack_log"""
        ).one()
    with get_db().snapshot() as snap:
        deploy_row = snap.execute_sql(
            "SELECT COUNT(*), COUNTIF(success = TRUE) FROM deploy_log WHERE cwe_id != 'blue-team'"
        ).one()
    return {
        'total':          row[0],
        'confirmed':      row[1],
        'unconfirmed':    row[2],
        'failed':         row[3],
        'deploy_total':   deploy_row[0],
        'deploy_success': deploy_row[1],
    }


def fetch_live():
    """Fetch in-progress run counts from the agent service. Returns zeros on failure."""
    counts = {'queued': 0, 'setting_up': 0, 'running': 0, 'in_progress': 0}
    try:
        resp = http.get(f'{AGENT_URL}/runs', timeout=3)
        resp.raise_for_status()
        for run in resp.json():
            s = run.get('status', '')
            if s in counts:
                counts[s] += 1
        counts['in_progress'] = counts['setting_up'] + counts['running']
    except Exception as e:
        logger.warning(f'fetch_live failed: {e}')
    return counts


def fetch_attacks():
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            """SELECT
                 a.id,
                 a.attempted_at,
                 a.cwe_id,
                 COALESCE(c.name,  '—')   AS cwe_name,
                 COALESCE(c.rank,  0)      AS cwe_rank,
                 COALESCE(c.score, 0.0)    AS cwe_score,
                 a.status,
                 a.target_url,
                 a.payload,
                 a.evidence
               FROM attack_log a
               LEFT JOIN cwe_registry c USING (cwe_id)
               ORDER BY a.attempted_at DESC"""
        )
        for r in rows:
            ts = r[1]
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            results.append({
                'id':           r[0],
                'attempted_at': ts,
                'cwe_id':       r[2],
                'cwe_name':     r[3],
                'cwe_rank':     r[4],
                'cwe_score':    float(r[5]),
                'status':       r[6],
                'target_url':   r[7] or '—',
                'payload':      (r[8] or '')[:120],
                'evidence':     (r[9] or '')[:200],
            })
    return results


def fetch_attack(attack_id):
    with get_db().snapshot() as snap:
        rows = list(snap.execute_sql(
            """SELECT
                 a.id,
                 a.attempted_at,
                 a.cwe_id,
                 COALESCE(c.name,  '—')  AS cwe_name,
                 COALESCE(c.rank,  0)    AS cwe_rank,
                 COALESCE(c.score, 0.0)  AS cwe_score,
                 a.status,
                 a.target_url,
                 a.payload,
                 a.evidence
               FROM attack_log a
               LEFT JOIN cwe_registry c USING (cwe_id)
               WHERE a.id = @id""",
            params={'id': attack_id},
            param_types={'id': spanner.param_types.STRING},
        ))
    if not rows:
        return None
    r = rows[0]
    ts = r[1]
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return {
        'id':           r[0],
        'attempted_at': ts,
        'cwe_id':       r[2],
        'cwe_name':     r[3],
        'cwe_rank':     r[4],
        'cwe_score':    float(r[5]),
        'status':       r[6],
        'target_url':   r[7] or '—',
        'payload':      r[8] or '',
        'evidence':     r[9] or '',
    }


def fetch_exploits():
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            """SELECT
                 a.id,
                 a.attempted_at,
                 a.cwe_id,
                 COALESCE(c.name,  '—')  AS cwe_name,
                 COALESCE(c.rank,  0)    AS cwe_rank,
                 COALESCE(c.score, 0.0)  AS cwe_score,
                 a.target_url,
                 a.payload,
                 a.evidence,
                 a.run_id
               FROM attack_log a
               LEFT JOIN cwe_registry c USING (cwe_id)
               WHERE a.status = 'confirmed'
               ORDER BY a.attempted_at DESC"""
        )
        for r in rows:
            ts = r[1]
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            results.append({
                'id':           r[0],
                'attempted_at': ts,
                'cwe_id':       r[2],
                'cwe_name':     r[3],
                'cwe_rank':     r[4],
                'cwe_score':    float(r[5]),
                'target_url':   r[6] or '—',
                'payload':      r[7] or '',
                'evidence':     r[8] or '',
                'run_id':       r[9] or '',
            })
    return results


def fetch_runs():
    try:
        resp = http.get(f'{AGENT_URL}/runs', timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f'fetch_runs failed: {e}')
        return []


def fetch_blue_runs():
    try:
        resp = http.get(f'{BLUE_TEAM_URL}/runs', timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f'fetch_blue_runs failed: {e}')
        return []


def fetch_agent_runs(team=None, limit=200):
    """List persisted agent runs from Spanner, newest first. team='red'|'blue'|None."""
    sql = ("SELECT id, team, status, instructions, detail, started_at, ended_at "
           "FROM agent_runs ")
    params, types = {}, {}
    if team in ('red', 'blue'):
        sql += "WHERE team = @team "
        params['team'], types['team'] = team, spanner.param_types.STRING
    sql += "ORDER BY started_at DESC LIMIT @lim"
    params['lim'], types['lim'] = limit, spanner.param_types.INT64
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(sql, params=params, param_types=types)
        for r in rows:
            started, ended = r[5], r[6]
            if started and started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            if ended and ended.tzinfo is None:
                ended = ended.replace(tzinfo=timezone.utc)
            duration = int((ended - started).total_seconds()) if (ended and started) else None
            results.append({
                'id':           r[0],
                'team':         r[1],
                'status':       r[2],
                'instructions': r[3] or '',
                'detail':       r[4] or '',
                'started_at':   started,
                'ended_at':     ended,
                'duration_s':   duration,
            })
    return results


def fetch_agent_run(run_id):
    """One persisted agent run with full step list and gather_findings."""
    import json
    with get_db().snapshot() as snap:
        rows = list(snap.execute_sql(
            "SELECT id, team, status, instructions, detail, gather_findings, "
            "steps_json, started_at, ended_at "
            "FROM agent_runs WHERE id = @id",
            params={'id': run_id},
            param_types={'id': spanner.param_types.STRING},
        ))
    if not rows:
        return None
    r = rows[0]
    started, ended = r[7], r[8]
    if started and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if ended and ended.tzinfo is None:
        ended = ended.replace(tzinfo=timezone.utc)
    try:
        steps = json.loads(r[6]) if r[6] else []
    except Exception:
        steps = []
    return {
        'id':              r[0],
        'team':            r[1],
        'status':          r[2],
        'instructions':    r[3] or '',
        'detail':          r[4] or '',
        'gather_findings': r[5] or '',
        'steps':           steps,
        'started_at':      started,
        'ended_at':        ended,
        'duration_s':      int((ended - started).total_seconds()) if (ended and started) else None,
    }


def fetch_blue_live():
    """Fetch in-progress run counts from the blue team agent."""
    counts = {'queued': 0, 'running': 0, 'in_progress': 0}
    try:
        resp = http.get(f'{BLUE_TEAM_URL}/runs', timeout=3)
        resp.raise_for_status()
        for run in resp.json():
            s = run.get('status', '')
            if s == 'queued':
                counts['queued'] += 1
                counts['in_progress'] += 1
            elif s in ('running', 'setting_up', 'waiting'):
                counts['running'] += 1
                counts['in_progress'] += 1
    except Exception as e:
        logger.warning(f'fetch_blue_live failed: {e}')
    return counts


def fetch_blue_stats():
    """Fetch blue team defense + deploy totals."""
    out = {'total': 0, 'fixed': 0, 'deploy_total': 0, 'deploy_success': 0}
    try:
        with get_db().snapshot() as snap:
            row = snap.execute_sql(
                'SELECT COUNT(*), COUNTIF(fixed = TRUE) FROM defense_log'
            ).one()
        out['total'], out['fixed'] = row[0], row[1]
    except Exception as e:
        logger.warning(f'fetch_blue_stats (defense) failed: {e}')
    try:
        with get_db().snapshot() as snap:
            row = snap.execute_sql(
                "SELECT COUNT(*), COUNTIF(success = TRUE) FROM deploy_log WHERE cwe_id = 'blue-team'"
            ).one()
        out['deploy_total'], out['deploy_success'] = row[0], row[1]
    except Exception as e:
        logger.warning(f'fetch_blue_stats (deploy) failed: {e}')
    return out


def fetch_defenses():
    """Flat list of defense_log entries (one row per defense, joined with CWE info).
    Used by the /defenses page; the leaderboard index uses fetch_defense_groups()."""
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            """SELECT d.id, d.attack_id, d.target_url, d.fixed, d.evidence, d.attempted_at, d.run_id,
                      COALESCE(a.cwe_id, '')  AS cwe_id,
                      COALESCE(c.name,   '—') AS cwe_name,
                      COALESCE(c.rank,   0)   AS cwe_rank
               FROM defense_log d
               LEFT JOIN attack_log   a ON a.id     = d.attack_id
               LEFT JOIN cwe_registry c ON c.cwe_id = a.cwe_id
               ORDER BY d.attempted_at DESC"""
        )
        for r in rows:
            ts = r[5]
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            results.append({
                'id':           r[0],
                'attack_id':    r[1] or '',
                'target_url':   r[2] or '—',
                'fixed':        r[3],
                'evidence':     (r[4] or '')[:400],
                'attempted_at': ts,
                'run_id':       r[6] or '',
                'cwe_id':       r[7] or '',
                'cwe_name':     r[8],
                'cwe_rank':     r[9],
            })
    return results


def fetch_defense_groups():
    """Grouped view: one entry per blue-team scan (by run_id), with all CWEs
    fixed/not-fixed in that scan. Defenses with NULL run_id (legacy rows from
    before the schema change) each get their own group keyed on entry id."""
    raw = fetch_defenses()
    groups = {}  # group_key → group dict
    order = []   # preserve newest-first ordering
    for d in raw:
        gk = d['run_id'] or f"_solo:{d['id']}"
        g = groups.get(gk)
        if g is None:
            g = {
                'run_id':       d['run_id'],
                'group_key':    gk,
                'attempted_at': d['attempted_at'],
                'cwes_by_id':   {},   # cwe_id → {cwe_id, cwe_name, cwe_rank, fixed}
                'fixed_count':  0,
                'total_count':  0,
                'evidences':    [],
                'target_urls':  set(),
            }
            groups[gk] = g
            order.append(gk)
        # Dedupe CWE entries within a group; a CWE is fixed only if EVERY
        # defense for that CWE in this scan succeeded.
        cwe = g['cwes_by_id'].get(d['cwe_id'])
        if cwe is None:
            g['cwes_by_id'][d['cwe_id']] = {
                'cwe_id':   d['cwe_id'],
                'cwe_name': d['cwe_name'],
                'cwe_rank': d['cwe_rank'],
                'fixed':    bool(d['fixed']),
            }
        else:
            cwe['fixed'] = cwe['fixed'] and bool(d['fixed'])
        g['total_count'] += 1
        if d['fixed']:
            g['fixed_count'] += 1
        if d['target_url'] and d['target_url'] != '—':
            g['target_urls'].add(d['target_url'])
        if d['evidence']:
            g['evidences'].append(d['evidence'][:160])

    out = []
    for gk in order:
        g = groups[gk]
        cwes = list(g.pop('cwes_by_id').values())
        cwes.sort(key=lambda x: (x['cwe_rank'] or 9999, x['cwe_id']))
        g['cwes'] = cwes
        g['target_urls'] = sorted(g['target_urls'])
        out.append(g)
    return out


def fetch_cwe_registry():
    """Return every row in cwe_registry with plan field counts and live
    attack/defense counts. Used by /cwes."""
    out = []
    sql = """
      SELECT
        c.cwe_id, c.name, c.rank, c.score, c.applicable,
        c.suspect_paths, c.code_patterns, c.log_patterns, c.plan_notes,
        (SELECT COUNT(*) FROM attack_log a WHERE a.cwe_id = c.cwe_id) AS attempts,
        (SELECT COUNT(*) FROM attack_log a
          WHERE a.cwe_id = c.cwe_id AND a.status = 'confirmed') AS confirmed,
        (SELECT COUNT(*)
           FROM defense_log d
           JOIN attack_log  a ON a.id = d.attack_id
           WHERE a.cwe_id = c.cwe_id AND d.fixed = TRUE) AS fixes
      FROM cwe_registry c
      ORDER BY c.rank ASC
    """
    with get_db().snapshot() as snap:
        for r in snap.execute_sql(sql):
            suspect_paths = list(r[5] or [])
            code_patterns = list(r[6] or [])
            log_patterns  = list(r[7] or [])
            plan_notes    = r[8] or ''
            is_planned    = bool(suspect_paths or code_patterns or log_patterns or plan_notes)
            out.append({
                'cwe_id':              r[0],
                'name':                r[1],
                'rank':                r[2],
                'score':                float(r[3]),
                'applicable':          r[4],
                'suspect_paths':       suspect_paths,
                'code_patterns':       code_patterns,
                'log_patterns':        log_patterns,
                'plan_notes':          plan_notes,
                'is_planned':          is_planned,
                'attempts':            r[9],
                'confirmed_exploits':  r[10],
                'fixes':               r[11],
            })
    return out


def fetch_cwe_detail(cwe_id):
    """Single CWE registry row for the detail page."""
    sql = """
      SELECT
        c.cwe_id, c.name, c.rank, c.score, c.applicable,
        c.suspect_paths, c.code_patterns, c.log_patterns, c.plan_notes,
        (SELECT COUNT(*) FROM attack_log a WHERE a.cwe_id = c.cwe_id) AS attempts,
        (SELECT COUNT(*) FROM attack_log a
          WHERE a.cwe_id = c.cwe_id AND a.status = 'confirmed') AS confirmed,
        (SELECT COUNT(*)
           FROM defense_log d
           JOIN attack_log  a ON a.id = d.attack_id
           WHERE a.cwe_id = c.cwe_id AND d.fixed = TRUE) AS fixes
      FROM cwe_registry c
      WHERE c.cwe_id = @cwe_id
    """
    with get_db().snapshot() as snap:
        rows = list(snap.execute_sql(
            sql,
            params={'cwe_id': cwe_id},
            param_types={'cwe_id': spanner.param_types.STRING},
        ))
    if not rows:
        return None
    r = rows[0]
    suspect_paths = list(r[5] or [])
    code_patterns = list(r[6] or [])
    log_patterns  = list(r[7] or [])
    plan_notes    = r[8] or ''
    is_planned    = bool(suspect_paths or code_patterns or log_patterns or plan_notes)
    return {
        'cwe_id':             r[0],
        'name':               r[1],
        'rank':               r[2],
        'score':               float(r[3]),
        'applicable':         r[4],
        'suspect_paths':      suspect_paths,
        'code_patterns':      code_patterns,
        'log_patterns':       log_patterns,
        'plan_notes':         plan_notes,
        'is_planned':         is_planned,
        'attempts':           r[9],
        'confirmed_exploits': r[10],
        'fixes':              r[11],
    }


def fetch_deploys(team=None):
    """Fetch deploys. team='blue' filters to blue team only; 'red' excludes blue team."""
    results = []
    sql = 'SELECT id, cwe_id, attempted_at, success, detail FROM deploy_log'
    if team == 'blue':
        sql += " WHERE cwe_id = 'blue-team'"
    elif team == 'red':
        sql += " WHERE cwe_id != 'blue-team'"
    sql += ' ORDER BY attempted_at DESC'
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(sql)
        for r in rows:
            ts = r[2]
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            results.append({
                'id':           r[0],
                'cwe_id':       r[1],
                'attempted_at': ts,
                'success':      r[3],
                'detail':       (r[4] or '')[:300],
            })
    return results



@app.route('/')
def index():
    stats      = fetch_stats()
    live       = fetch_live()
    attacks    = fetch_attacks()
    defenses   = fetch_defense_groups()  # one row per scan
    blue_stats = fetch_blue_stats()
    blue_live  = fetch_blue_live()
    return render_template('index.html', stats=stats, live=live, attacks=attacks,
                           defenses=defenses, blue_stats=blue_stats, blue_live=blue_live)


@app.route('/attacks/<attack_id>')
def attack_detail(attack_id):
    attack = fetch_attack(attack_id)
    if not attack:
        abort(404)
    return render_template('attack.html', attack=attack)


@app.route('/exploits')
def exploits_page():
    return render_template('exploits.html', exploits=fetch_exploits())


@app.route('/runs')
def runs_page():
    return render_template('runs.html', runs=fetch_runs())


@app.route('/blue-runs')
def blue_runs_page():
    return render_template('blue_runs.html', runs=fetch_blue_runs())


@app.route('/agent-runs')
def agent_runs_page():
    from flask import request
    team = request.args.get('team', '').lower() or None
    if team not in ('red', 'blue', None):
        team = None
    return render_template('agent_runs.html', runs=fetch_agent_runs(team), team=team)


@app.route('/agent-runs/<run_id>')
def agent_run_detail(run_id):
    run = fetch_agent_run(run_id)
    if not run:
        abort(404)
    return render_template('agent_run_detail.html', run=run)


@app.route('/defenses')
def defenses_page():
    return render_template('defenses.html', defenses=fetch_defenses())


@app.route('/cwes')
def cwes_page():
    return render_template('cwes.html', cwes=fetch_cwe_registry())


@app.route('/cwes/<cwe_id>')
def cwe_detail(cwe_id):
    cwe = fetch_cwe_detail(cwe_id)
    if not cwe:
        abort(404)
    return render_template('cwe_detail.html', cwe=cwe)


@app.route('/deploys')
def deploys_page():
    from flask import request
    team = request.args.get('team', '').lower() or None
    if team not in ('red', 'blue', None):
        team = None
    return render_template('deploys.html', deploys=fetch_deploys(team), team=team)



@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
