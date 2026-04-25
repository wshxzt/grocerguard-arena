import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    _project = os.environ.get('SPANNER_PROJECT_ID', '')
    _instance = os.environ.get('SPANNER_INSTANCE_ID', '')
    _database = os.environ.get('SPANNER_DATABASE_ID', 'grocerguard')

    if _project and _instance:
        SQLALCHEMY_DATABASE_URI = (
            f'spanner+spanner:///projects/{_project}/instances/{_instance}/databases/{_database}'
        )
        SESSION_COOKIE_SECURE = True
    else:
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///grocerguard.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GCS_BUCKET_NAME = os.environ.get('GCS_BUCKET_NAME', '')
    WTF_CSRF_ENABLED = True
