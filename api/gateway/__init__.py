from flask import Blueprint

bp = Blueprint('gateway', __name__)

from api.gateway import routes
