from flask import Blueprint

bp = Blueprint('auth', __name__)

from api.auth import models, schemas, routes
