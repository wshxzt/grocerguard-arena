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
                 a.evidence
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
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            """SELECT d.id, d.attack_id, d.target_url, d.fixed, d.evidence, d.attempted_at,
                      COALESCE(a.cwe_id, '')          AS cwe_id,
                      COALESCE(c.name,   '—')         AS cwe_name,
                      COALESCE(c.rank,   0)           AS cwe_rank
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
                'cwe_id':       r[6] or '',
                'cwe_name':     r[7],
                'cwe_rank':     r[8],
            })
    return results


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
    defenses   = fetch_defenses()
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
