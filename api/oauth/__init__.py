"""api/oauth/__init.py__"""

from flask import Blueprint

bp = Blueprint('oauth', __name__, url_prefix='/api')

from api.oauth import models, oauth2, routes
