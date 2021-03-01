from functools import wraps
from flask import request, g

from api.auth.models import User, Token


class CustomAuth(object):
    """Custom authentication base class"""

    def __init__(self):
        self.auth_error_callback = None

        def default_auth_error():
            return ({'errors': [{
                     'detail': 'Invalid request details',
                     'status': '401',
                     'title': 'Unauthorized'}]},
                    401)

        self.error_handler(default_auth_error)

    def error_handler(self, f):
        """Error handling callback"""
        self.auth_error_callback = f
        return f

    def login_required(self, f):
        """Decorator function to check authentication"""
        @wraps(f)
        def wrap(*args, **kwargs):
            if not self.authenticate():
                return self.auth_error_callback()

            # finally call f. f() now have access to g.user
            return f(*args, **kwargs)
        return wrap


class CustomPassAuth(CustomAuth):
    """Custom authentication class for password handling"""

    def __init__(self):
        super(CustomPassAuth, self).__init__()
        self.verify_password_callback = None

    def verify_password(self, f):
        """Verify password callback"""
        self.verify_password_callback = f
        return f

    def authenticate(self):
        """Returns callback function for
        password authentication
        """
        if self.verify_password_callback:
            return self.verify_password_callback()
        return False


class CustomTokenAuth(CustomAuth):
    """Custom authentication class for token handling"""

    def __init__(self):
        super(CustomTokenAuth, self).__init__()
        self.verify_token_callback = None

    def verify_token(self, f):
        """Verify token callback"""
        self.verify_token_callback = f
        return f

    def authenticate(self):
        """Returns callback function for
        token authentication
        """
        if self.verify_token_callback:
            return self.verify_token_callback()
        return False


# Custom authentication objects
pwd = CustomPassAuth()
tok = CustomTokenAuth()


@pwd.verify_password
def verify_password():
    """Callback function to validate username and password

    :returns: Boolean
    """

    # Check the request data arguments
    info = request.json.get('data')
    if info is None or 'attributes' not in info:
        return False

    email = info['attributes'].get('email')
    password = info['attributes'].get('userPassword')
    if email is None or password is None:
        return False

    # Validate password
    user = User.query.filter(User.username == email).first()
    if not user or not user.verify_password(password):
        return False

    # Make user available down the pipeline via flask.g
    g.user = user
    return True


@tok.verify_token
def verify_token():
    """Callback function to validate token

    :returns: Boolean
    """

    # Check the request header
    tokenRequest = request.headers.get('Token')
    if tokenRequest is None:
        return False

    # Validate token
    userToken = Token.query.filter(
        Token.token == tokenRequest).one_or_none()
    if not userToken:
        return False

    # Make user available down the pipeline via flask.g
    g.user = User.query.get(userToken.user_id)
    if not g.user:
        return False

    return True
