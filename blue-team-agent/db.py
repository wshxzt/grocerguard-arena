"""Spanner client for Blue Team Agent."""
import os
import uuid
from datetime import datetime, timezone
from google.cloud import spanner

PROJECT  = os.environ.get('SPANNER_PROJECT_ID', '')
INSTANCE = os.environ.get('SPANNER_INSTANCE_ID', '')
DATABASE = os.environ.get('SPANNER_DATABASE_ID', 'grocerguard')

_db = None

def get_db():
    global _db
    if _db is None:
        if not PROJECT or not INSTANCE:
            raise ValueError("SPANNER_PROJECT_ID and SPANNER_INSTANCE_ID must be set")
        client   = spanner.Client(project=PROJECT)
        instance = client.instance(INSTANCE)
        _db      = instance.database(DATABASE)
    return _db


def get_recent_attacks(limit=5):
    """Fetch recent attacks to find payloads for verification."""
    with get_db().snapshot() as snap:
        rows = list(snap.execute_sql(
            'SELECT id, cwe_id, target_url, payload, evidence '
            'FROM attack_log '
            'WHERE status IN ("confirmed", "unconfirmed") '
            'ORDER BY attempted_at DESC LIMIT @limit',
            params={'limit': limit},
            param_types={'limit': spanner.param_types.INT64},
        ))
    
    attacks = []
    for row in rows:
        attacks.append({
            'attack_id': row[0],
            'cwe_id': row[1],
            'target_url': row[2],
            'payload': row[3],
            'evidence': row[4],
        })
    return attacks


def log_defense(attack_id, target_url, fixed, evidence):
    """Log the outcome of a defense run."""
    now = datetime.now(timezone.utc)
    with get_db().batch() as batch:
        batch.insert(
            table='defense_log',
            columns=['id', 'attack_id', 'target_url', 'fixed', 'evidence', 'attempted_at'],
            values=[(str(uuid.uuid4()), attack_id, target_url, fixed, evidence, now)]
        )


def log_deploy(success, detail=''):
    """Log a blue team deploy."""
    now = datetime.now(timezone.utc)
    with get_db().batch() as batch:
        batch.insert(
            table='deploy_log',
            columns=['id', 'cwe_id', 'attempted_at', 'success', 'detail'],
            values=[(str(uuid.uuid4()), 'blue-team', now, success, detail[:500])]
        )
