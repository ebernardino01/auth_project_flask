import datetime
from functools import wraps
from flask import current_app
from sqlalchemy import Sequence, text, exc
from marshmallow_jsonapi import fields
from marshmallow_jsonapi.flask import Schema
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

from api import db


# Get the id sequence value to be used based from data center location
sequence = current_app.config['DC_SEQ_DEFAULT']
sql = text('SELECT current_id_sequence FROM location WHERE name = :param;')
result = db.session.execute(sql,
                            {"param": current_app.config['DC_LOCATION']})

# Get ResultProxy object
if result:
    # Get RowProxy object
    row = result.first()
    if row:
        sequence = row['current_id_sequence']


TABLE_ID = Sequence('users_id_seq', start=sequence)

# User model class
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.BigInteger, TABLE_ID, primary_key=True,
                   server_default=TABLE_ID.next_value())
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    firstname = db.Column(db.String(255))
    lastname = db.Column(db.String(255))
    address = db.Column(db.String(255))
    contact = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean, default=False)
    created_on = db.Column(db.DateTime(timezone=True),
                           default=datetime.datetime.now)

    @property
    def fullname_value(self):
        if self.firstname or self.lastname is None:
            return ''
        return self.firstname + ' ' + self.lastname

    @property
    def created_on_value(self):
        return self.created_on.strftime("%Y-%m-%d %H:%M:%S %z")

    # Stores password as converted hash
    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    # Validates password
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    # Creates authentication token using secret key and user id
    def generate_auth_token(self,
                        expiration=current_app.config['TOKEN_TIME']):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id})

    # Validates token
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


# User object serialization schema class
class UserSchema(Schema):
    id = fields.Str(dump_only=True)

    class Meta:
        type_ = "users"
        strict = True
        self_view = "auth.get_user"
        self_view_kwargs = {"id": "<id>"}
        self_view_many = "auth.get_all_user"

        # Fields to expose
        fields = ("id", "username", "fullname_value", "address",
                  "contact", "is_admin", "created_on_value")

# Custom authentication base class
class CustomAuth(object):
    def __init__(self):
        self.auth_error_callback = None
        def default_auth_error():
            return ({'errors': [{
                     'detail': 'Invalid request details',
                     'status': '401',
                     'title': 'Unauthorized'}]},
                     401)

        self.error_handler(default_auth_error)

    # Error handling callback
    def error_handler(self, f):
        self.auth_error_callback = f
        return f

    # Decorator function to check authentication
    def login_required(self, f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if not self.authenticate():
                return self.auth_error_callback()

            # finally call f. f() now have access to g.user
            return f(*args, **kwargs)
        return wrap


# Custom authentication class for password handling
class CustomPassAuth(CustomAuth):
    def __init__(self):
        super(CustomPassAuth, self).__init__()
        self.verify_password_callback = None

    # Verify password callback
    def verify_password(self, f):
        self.verify_password_callback = f
        return f

    def authenticate(self):
        if self.verify_password_callback:
            return self.verify_password_callback()
        return False


# Custom authentication class for token handling
class CustomTokenAuth(CustomAuth):
    def __init__(self):
        super(CustomTokenAuth, self).__init__()
        self.verify_token_callback = None

    # Verify token callback
    def verify_token(self, f):
        self.verify_token_callback = f
        return f

    def authenticate(self):
        if self.verify_token_callback:
            return self.verify_token_callback()
        return False
