import datetime


class GCSService:
    """Google Cloud Storage integration for product images.

    Falls back gracefully when credentials are not configured — callers
    check is_configured() and use a placeholder URL instead.
    """

    def __init__(self, bucket_name: str):
        self.bucket_name = bucket_name
        self._client = None
        self._bucket = None

    def is_configured(self) -> bool:
        return bool(self.bucket_name)

    def _get_bucket(self):
        if not self._bucket:
            from google.cloud import storage
            self._client = storage.Client()
            self._bucket = self._client.bucket(self.bucket_name)
        return self._bucket

    def upload_file(self, file_obj, destination_path: str, content_type: str = 'image/jpeg') -> str:
        """Upload a file-like object and return the GCS object path."""
        blob = self._get_bucket().blob(destination_path)
        blob.upload_from_file(file_obj, content_type=content_type)
        return destination_path

    def get_public_url(self, blob_path: str) -> str:
        """Return the public HTTPS URL for a GCS object (bucket must be public)."""
        return f'https://storage.googleapis.com/{self.bucket_name}/{blob_path}'

    def get_signed_url(self, blob_path: str, expiration_minutes: int = 60) -> str:
        """Generate a time-limited signed URL for a GCS object."""
        blob = self._get_bucket().blob(blob_path)
        return blob.generate_signed_url(
            expiration=datetime.timedelta(minutes=expiration_minutes),
            method='GET',
        )

    def delete_file(self, blob_path: str) -> None:
        self._get_bucket().blob(blob_path).delete()
