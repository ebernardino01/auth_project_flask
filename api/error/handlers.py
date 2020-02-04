import jsonschema
from flask import current_app
from werkzeug.http import HTTP_STATUS_CODES

from api.error import bp

def error_response(status_code, message=None):
    payload = {}
    payload["status"] = str(status_code)
    payload["title"] = HTTP_STATUS_CODES.get(status_code, 'Unknown error')
    if message:
        payload["detail"] = message
    return ({"errors": [payload]}, status_code)

def bad_request(message):
    return error_response(400, message)

def not_found(message):
    return error_response(404, message)

def duplicate(message):
    return error_response(409, message)

@bp.app_errorhandler(jsonschema.ValidationError)
def onValidationError(e):
    return error_response(400, "There was a validation error: " + e.message)
