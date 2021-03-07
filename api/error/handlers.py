"""api/error/handlers.py"""

import jsonschema
from werkzeug.http import HTTP_STATUS_CODES

from api.error import bp


def error_response(status_code, message=None):
    """Custom JSONAPI compliant error response builder

    :param int status_code: HTTP status code
    :param string message: error message
    :returns: dict
    """

    payload = {}
    payload["status"] = str(status_code)
    payload["title"] = HTTP_STATUS_CODES.get(status_code, 'Unknown error')
    payload["code"] = status_code
    if message:
        payload["detail"] = message
    return ({"errors": [payload]}, status_code)


def bad_request(message):
    """JSONAPI bad request error response"""

    return error_response(400, message)


def unauthorized(message):
    """JSONAPI unauthorized error response"""

    return error_response(401, message)


def not_found(message):
    """JSONAPI not found error response"""

    return error_response(404, message)


def duplicate(message):
    """JSONAPI duplicate error response"""

    return error_response(409, message)


@bp.app_errorhandler(jsonschema.ValidationError)
def onValidationError(err):
    """JSONSchema validation error response"""

    return error_response(400, "There was a validation error: " + err.message)


class ApiException(Exception):
    """Custom JSONAPI compliant Rest API Exception wrapper"""

    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        """Initialize an instance of ApiException

        :param string message: exception message
        :param int status_code: HTTP status code
        :param dict payload: exception details
        """

        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def error_response(self):
        """JSONAPI compliant Rest API error response

        :returns: dict
        """

        error = dict(self.payload or ())
        error["status"] = str(self.status_code)
        error["title"] = HTTP_STATUS_CODES.get(self.status_code, 'Unknown error')
        error["code"] = self.status_code
        error['detail'] = self.message
        return ({"errors": [error]}, self.status_code)
