"""GrocerGuard Arena Leaderboard."""
import os
import logging
from datetime import timezone
import requests as http
from flask import Flask, render_template, abort
from google.cloud import spanner

logger = logging.getLogger(__name__)

AGENT_URL = os.environ.get('AGENT_URL', 'https://red-team-agent-hfzinwetfq-uc.a.run.app')

app = Flask(__name__)

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
            'SELECT COUNT(*), COUNTIF(success = TRUE) FROM deploy_log'
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


def fetch_deploys():
    results = []
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            'SELECT id, cwe_id, attempted_at, success, detail '
            'FROM deploy_log ORDER BY attempted_at DESC'
        )
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
    stats   = fetch_stats()
    live    = fetch_live()
    attacks = fetch_attacks()
    return render_template('index.html', stats=stats, live=live, attacks=attacks)


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


@app.route('/deploys')
def deploys_page():
    return render_template('deploys.html', deploys=fetch_deploys())


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
