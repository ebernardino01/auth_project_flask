from flask import Blueprint

bp = Blueprint('error', __name__)

from api.error import handlers
