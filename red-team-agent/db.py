"""Spanner client for CWE registry and attack log."""
import os
import uuid
from datetime import datetime, timezone
from google.cloud import spanner

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


def upsert_cwe(cwe_id, name, rank, score, rank_delta, applicable):
    get_db().run_in_transaction(lambda tx: tx.execute_update(
        """INSERT OR UPDATE INTO cwe_registry
           (cwe_id, name, rank, score, rank_delta, applicable, last_synced)
           VALUES (@cwe_id, @name, @rank, @score, @rank_delta, @applicable, @ts)""",
        params=dict(cwe_id=cwe_id, name=name, rank=rank, score=score,
                    rank_delta=rank_delta, applicable=applicable,
                    ts=datetime.now(timezone.utc)),
        param_types={
            'cwe_id':     spanner.param_types.STRING,
            'name':       spanner.param_types.STRING,
            'rank':       spanner.param_types.INT64,
            'score':      spanner.param_types.FLOAT64,
            'rank_delta': spanner.param_types.INT64,
            'applicable': spanner.param_types.BOOL,
            'ts':         spanner.param_types.TIMESTAMP,
        }
    ))


def get_cwe(cwe_id):
    with get_db().snapshot() as snap:
        rows = list(snap.execute_sql(
            'SELECT cwe_id, name, rank, score FROM cwe_registry WHERE cwe_id = @cwe_id',
            params={'cwe_id': cwe_id},
            param_types={'cwe_id': spanner.param_types.STRING},
        ))
    if not rows:
        return None
    cwe_id, name, rank, score = rows[0]
    return {'cwe_id': cwe_id, 'name': name, 'rank': rank, 'score': float(score)}


def get_next_cwe():
    db = get_db()
    with db.snapshot() as snap:
        tried = {r[0] for r in snap.execute_sql(
            'SELECT DISTINCT cwe_id FROM attack_log'
        )}
        for row in snap.execute_sql(
            'SELECT cwe_id, name, rank, score FROM cwe_registry '
            'WHERE applicable = TRUE ORDER BY score DESC'
        ):
            cwe_id, name, rank, score = row
            if cwe_id not in tried:
                return {'cwe_id': cwe_id, 'name': name, 'rank': rank, 'score': float(score)}
    return None


def log_finding(cwe_id, target_url, payload, status, evidence):
    now = datetime.now(timezone.utc)
    with get_db().batch() as batch:
        batch.insert(
            table='attack_log',
            columns=['id', 'cwe_id', 'target_url', 'payload', 'status', 'evidence', 'attempted_at'],
            values=[(str(uuid.uuid4()), cwe_id, target_url, payload, status, evidence, now)]
        )
