"""api/__init.py__"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jsonschema_validator import JSONSchemaValidator
from flask_executor import Executor
from flask_redis import FlaskRedis
from flask import Flask
from config import Config


# Sqlalchemy ORM object
db = SQLAlchemy()

# Migrate object
migrate = Migrate()

# Flask executor object
executor = Executor()

# Redis object
redis_client = FlaskRedis()


def refresh_cache():
    """Reset redis cache values on startup"""

    for key in redis_client.hkeys('USER_LIST_HASH'):
        redis_client.hdel('USER_LIST_HASH', key)

    for key in redis_client.hkeys('USER_ITEM_HASH'):
        redis_client.hdel('USER_ITEM_HASH', key)

    for key in redis_client.hkeys('OAUTH2_CLIENT_LIST_HASH'):
        redis_client.hdel('OAUTH2_CLIENT_LIST_HASH', key)

    for key in redis_client.hkeys('OAUTH2_CLIENT_DETAIL_HASH'):
        redis_client.hdel('OAUTH2_CLIENT_DETAIL_HASH', key)


def create_app(config_class=Config):
    """Application factory

    :param object config_class: Configuration class

    :returns: Flask application instance
    """

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialization
    db.app = app
    db.init_app(app)
    migrate.init_app(app, db)
    JSONSchemaValidator(app, app.config['JSONSCHEMA_ROOT'])
    executor.init_app(app)
    redis_client.init_app(app)

    with app.app_context():
        from api.error import bp as error_bp
        from api.util import bp as util_bp
        from api.auth import bp as auth_bp
        from api.oauth import bp as oauth_bp
        from api.oauth.oauth2 import config_oauth

        # Configure oauth
        config_oauth(app)

        # Blueprint registration
        app.register_blueprint(error_bp)
        app.register_blueprint(util_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(oauth_bp)

        # DB initialization
        db.create_all()

        # Clear redis cache
        refresh_cache()

        return app
