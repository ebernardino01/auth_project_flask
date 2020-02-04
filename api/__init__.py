from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jsonschema_validator import JSONSchemaValidator

# sql objects
db = SQLAlchemy()
migrate = Migrate()

# application factory
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # initialization
    db.init_app(app)
    migrate.init_app(app, db)
    JSONSchemaValidator(app, app.config['JSONSCHEMA_ROOT'])

    # blueprint registration
    with app.app_context():
        from api.error import bp as error_bp
        from api.auth import bp as auth_bp
        from api.billing import bp as bill_bp
        from api.gateway import bp as gateway_bp

        app.register_blueprint(error_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(bill_bp)
        app.register_blueprint(gateway_bp)

        db.create_all()
        return app
