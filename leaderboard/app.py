"""GrocerGuard Red Team Leaderboard — reads attack_log from Spanner."""
import os
from datetime import timezone
from flask import Flask, render_template
from google.cloud import spanner

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
                 COUNT(*) AS total,
                 COUNTIF(status = 'confirmed')   AS confirmed,
                 COUNTIF(status = 'unconfirmed') AS unconfirmed,
                 COUNTIF(status = 'failed')       AS failed
               FROM attack_log"""
        ).one()
    return {
        'total':       row[0],
        'confirmed':   row[1],
        'unconfirmed': row[2],
        'failed':      row[3],
    }


def fetch_attacks():
    with get_db().snapshot() as snap:
        rows = snap.execute_sql(
            """SELECT
                 a.attempted_at,
                 a.cwe_id,
                 COALESCE(c.name,  '—')          AS cwe_name,
                 COALESCE(c.rank,  0)             AS cwe_rank,
                 COALESCE(c.score, 0.0)           AS cwe_score,
                 a.status,
                 a.target_url,
                 a.payload,
                 a.evidence
               FROM attack_log a
               LEFT JOIN cwe_registry c USING (cwe_id)
               ORDER BY a.attempted_at DESC"""
        )
        results = []
        for r in rows:
            attempted_at = r[0]
            if attempted_at and attempted_at.tzinfo is None:
                attempted_at = attempted_at.replace(tzinfo=timezone.utc)
            results.append({
                'attempted_at': attempted_at,
                'cwe_id':       r[1],
                'cwe_name':     r[2],
                'cwe_rank':     r[3],
                'cwe_score':    float(r[4]),
                'status':       r[5],
                'target_url':   r[6] or '—',
                'payload':      (r[7] or '')[:120],
                'evidence':     (r[8] or '')[:200],
            })
    return results


@app.route('/')
def index():
    stats   = fetch_stats()
    attacks = fetch_attacks()
    return render_template('index.html', stats=stats, attacks=attacks)


@app.route('/healthz')
def healthz():
    return 'ok', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
