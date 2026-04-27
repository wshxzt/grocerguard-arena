#!/bin/bash
# Build and deploy the blue-team-agent, bundling the grocerguard-app source inside the image.
set -e

PROJECT=zhiting-personal
REGION=us-central1
SERVICE=blue-team-agent
IMAGE="us-central1-docker.pkg.dev/$PROJECT/cloud-run-source-deploy/$SERVICE"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARENA_ROOT="$(dirname "$SCRIPT_DIR")"

BUILD_DIR="$(mktemp -d)"
trap "rm -rf $BUILD_DIR" EXIT

echo "Assembling build context in $BUILD_DIR..."
# Copy agent code into agent-src/ (matches Dockerfile COPY agent-src/ .)
mkdir -p "$BUILD_DIR/agent-src"
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='.venv' --exclude='deploy.sh' \
  "$SCRIPT_DIR/" "$BUILD_DIR/agent-src/"
# Put the Dockerfile at the root of the build context
mv "$BUILD_DIR/agent-src/Dockerfile" "$BUILD_DIR/Dockerfile"

# Copy grocerguard-app source into grocerguard-app-src/
mkdir -p "$BUILD_DIR/grocerguard-app-src"
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='instance' \
  "$ARENA_ROOT/grocerguard-app/" "$BUILD_DIR/grocerguard-app-src/"

echo "Submitting Cloud Build..."
gcloud builds submit "$BUILD_DIR" --tag "$IMAGE" --project "$PROJECT"

echo "Deploying to Cloud Run..."
gcloud run deploy "$SERVICE" \
  --image "$IMAGE" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --memory 1Gi \
  --timeout 3600 \
  --min-instances 1 \
  --max-instances 1 \
  --no-cpu-throttling \
  --set-env-vars "SPANNER_PROJECT_ID=$PROJECT,SPANNER_INSTANCE_ID=grocerguard-instance,SPANNER_DATABASE_ID=grocerguard,APP_BASE_URL=https://grocerguard-hfzinwetfq-uc.a.run.app,SCAN_INTERVAL_MINUTES=120" \
  --set-secrets "AGENT_API_KEY=grocerguard-secret-key:latest" \
  --project "$PROJECT"

echo "Done. Blue-team-agent deployed."
