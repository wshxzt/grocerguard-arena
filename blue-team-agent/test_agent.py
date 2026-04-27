"""
Local test harness for the blue-team agent.

The agent runs in a background thread and logs all ADK events to stdout.
It uses:
  - CODEBASE_DIR → deployable grocerguard-app source (write_file + deploy build from here)
  - inspect_deployed_filesystem → extracts live grocerguard container to /tmp/inspections/grocerguard/app/
  - http_request  → live grocerguard on Cloud Run
  - fetch_service_logs → live Cloud Run via gcloud
  - Spanner → live production database via ADC
"""
import os
import sys
import time
import threading
import logging

# ── GCP / Spanner config ──────────────────────────────────────────────────────
os.environ.setdefault('SPANNER_PROJECT_ID', 'zhiting-personal')
os.environ.setdefault('SPANNER_INSTANCE_ID', 'grocerguard-instance')
os.environ.setdefault('SPANNER_DATABASE_ID', 'grocerguard')

# ── Deployable codebase (write_file + deploy build from here) ─────────────────
os.environ.setdefault('CODEBASE_DIR', os.path.join(
    os.path.dirname(__file__), '..', 'grocerguard-app'
))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)

from agent import run_agent


def _run_in_thread(instructions: str):
    def on_progress(steps):
        for step in steps:
            text = step.get('text', str(step)) if isinstance(step, dict) else str(step)
            print(f"\n  [PROGRESS] {text[:400]}", flush=True)

    print(f"\n{'='*60}")
    print(f"Starting blue-team agent pipeline...")
    print(f"CODEBASE_DIR: {os.environ['CODEBASE_DIR']}")
    print(f"{'='*60}\n", flush=True)

    try:
        run_agent(instructions=instructions, on_progress=on_progress)
        print(f"\n{'='*60}")
        print("Pipeline complete.")
        print(f"{'='*60}\n", flush=True)
    except Exception as e:
        print(f"\n[ERROR] Pipeline failed: {e}", flush=True)
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    instructions = ''  # leave blank to let the pipeline run autonomously

    t = threading.Thread(target=_run_in_thread, args=(instructions,), daemon=True)
    t.start()

    print("Blue team pipeline running. Press Ctrl+C to stop.")
    try:
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
