"""Fetch the MITRE CWE Top 25 (2025) and sync to Spanner."""
import logging
import requests
from bs4 import BeautifulSoup
import db

logger = logging.getLogger(__name__)

TOP25_URL = 'https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html'

# CWEs exploitable in a Python/Flask web app
APPLICABLE = {
    'CWE-79',   # XSS
    'CWE-89',   # SQL Injection
    'CWE-352',  # CSRF
    'CWE-862',  # Missing Authorization
    'CWE-863',  # Incorrect Authorization
    'CWE-284',  # Improper Access Control
    'CWE-200',  # Information Exposure
    'CWE-306',  # Missing Authentication
    'CWE-639',  # IDOR
    'CWE-20',   # Improper Input Validation
}


def _parse_delta(text):
    text = text.strip().lstrip('+')
    if text in ('', 'N/A', '—', '-', 'New'):
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


def sync_cwes():
    logger.info(f'Fetching CWE Top 25 from {TOP25_URL}')
    resp = requests.get(TOP25_URL, timeout=30,
                        headers={'User-Agent': 'GrocerGuard-RedTeam/1.0'})
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, 'html.parser')

    # The page has multiple tables; find the one that contains CWE-NNN anchor links
    table = None
    for t in soup.find_all('table'):
        if t.find('a', href=lambda h: h and '/data/definitions/' in h):
            table = t
            break

    if not table:
        logger.error('CWE data table not found on page')
        return 0

    synced = 0
    for row in table.find_all('tr')[1:]:
        cols = row.find_all('td')
        if len(cols) < 4:
            continue
        try:
            rank      = int(cols[0].get_text(strip=True))
            cwe_id    = cols[1].get_text(strip=True)
            name      = cols[2].get_text(strip=True)
            score     = float(cols[3].get_text(strip=True))
            delta     = _parse_delta(cols[4].get_text() if len(cols) > 4 else '0')
            applicable = cwe_id in APPLICABLE
            db.upsert_cwe(cwe_id, name, rank, score, delta, applicable)
            synced += 1
        except (ValueError, IndexError) as e:
            logger.warning(f'Skipping row: {e}')

    logger.info(f'Synced {synced} CWEs ({len(APPLICABLE)} applicable to web apps)')
    return synced
