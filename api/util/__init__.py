from flask import Blueprint

bp = Blueprint('util', __name__)

from api.util import handlers
