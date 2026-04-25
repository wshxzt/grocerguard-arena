#!/usr/bin/env bash
# Deploy GrocerGuard to Cloud Run with Cloud Spanner.
# Usage: ./deploy.sh [project-id] [region]
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project)}"
REGION="${2:-us-central1}"
SERVICE="grocerguard"
IMAGE="gcr.io/${PROJECT}/${SERVICE}"
INSTANCE="grocerguard-instance"
DATABASE="grocerguard"

echo "==> Project: $PROJECT  Region: $REGION"

# 1. Enable required APIs
gcloud services enable \
  spanner.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  --project "$PROJECT"

# 2. Create Spanner instance (skips if already exists)
gcloud spanner instances create "$INSTANCE" \
  --config=regional-${REGION} \
  --description="GrocerGuard" \
  --processing-units=100 \
  --project "$PROJECT" 2>/dev/null || echo "Spanner instance already exists."

# 3. Create Spanner database
gcloud spanner databases create "$DATABASE" \
  --instance="$INSTANCE" \
  --project "$PROJECT" 2>/dev/null || echo "Spanner database already exists."

# 4. Create GCS bucket for product images
BUCKET="${PROJECT}-grocerguard-images"
gsutil mb -p "$PROJECT" -l "$REGION" "gs://${BUCKET}" 2>/dev/null || echo "Bucket already exists."

# 5. Create service account for Cloud Run
SA_NAME="grocerguard-sa"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="GrocerGuard Service Account" \
  --project "$PROJECT" 2>/dev/null || echo "Service account already exists."

# Grant Spanner access
gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/spanner.databaseUser"

# Grant GCS access
gsutil iam ch "serviceAccount:${SA_EMAIL}:roles/storage.objectAdmin" "gs://${BUCKET}"

# 6. Store SECRET_KEY in Secret Manager
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
printf '%s' "$SECRET_KEY" | gcloud secrets create grocerguard-secret-key \
  --data-file=- --project "$PROJECT" 2>/dev/null || \
  printf '%s' "$SECRET_KEY" | gcloud secrets versions add grocerguard-secret-key \
    --data-file=- --project "$PROJECT"

gcloud secrets add-iam-policy-binding grocerguard-secret-key \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --project "$PROJECT"

# 7. Build and push Docker image
gcloud builds submit --tag "$IMAGE" --project "$PROJECT" .

# 8. Deploy to Cloud Run
gcloud run deploy "$SERVICE" \
  --image "$IMAGE" \
  --region "$REGION" \
  --platform managed \
  --service-account "$SA_EMAIL" \
  --allow-unauthenticated \
  --set-env-vars "SPANNER_PROJECT_ID=${PROJECT},SPANNER_INSTANCE_ID=${INSTANCE},SPANNER_DATABASE_ID=${DATABASE},GCS_BUCKET_NAME=${BUCKET}" \
  --set-secrets "SECRET_KEY=grocerguard-secret-key:latest" \
  --min-instances 0 \
  --max-instances 5 \
  --project "$PROJECT"

echo ""
echo "==> Done! App URL:"
gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" \
  --format "value(status.url)"
