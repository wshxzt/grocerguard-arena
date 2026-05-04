#!/bin/bash
# Build and deploy the red-team-agent.
#
# Capped at one Cloud Run instance with no CPU throttling so that:
#   - in-memory run state isn't lost when Cloud Run rotates instances mid-run
#   - the background pipeline thread keeps running between requests
# min-instances=0 lets the service scale to zero when idle (cold-start a
# few seconds on first request, but no idle CPU billing).
set -e

PROJECT=zhiting-personal
REGION=us-central1
SERVICE=red-team-agent
IMAGE="us-central1-docker.pkg.dev/$PROJECT/cloud-run-source-deploy/$SERVICE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Submitting Cloud Build..."
gcloud builds submit "$SCRIPT_DIR" --tag "$IMAGE" --project "$PROJECT"

echo "Deploying to Cloud Run..."
gcloud run deploy "$SERVICE" \
  --image "$IMAGE" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --memory 1Gi \
  --timeout 3600 \
  --min-instances 0 \
  --max-instances 1 \
  --no-cpu-throttling \
  --project "$PROJECT"

echo "Done. Red-team-agent deployed."
