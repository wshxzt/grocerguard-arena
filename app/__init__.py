from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from app.config import Config
from app.models import db, User
from app.gcs import GCSService

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    app.gcs_service = GCSService(app.config.get('GCS_BUCKET_NAME', ''))

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    from app.routes.auth import auth
    from app.routes.products import products
    from app.routes.orders import orders
    from app.routes.admin import admin

    app.register_blueprint(auth)
    app.register_blueprint(products)
    app.register_blueprint(orders)
    app.register_blueprint(admin)

    @app.route('/healthz')
    def health():
        return 'ok', 200

    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            app.logger.warning(f'db.create_all() skipped: {e}')

    return app
