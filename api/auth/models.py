"""api/auth/models.py"""

import datetime
import secrets
from flask import current_app
from sqlalchemy import Sequence, text
# from sqlalchemy.dialects.postgresql.json import JSONB
from passlib.apps import custom_app_context as pwd_context

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


class User(db.Model):
    """User sqlalchemy model class"""

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
    # info = db.Column(JSONB)
    client = None

    def get_user_id(self):
        """Get user id value

        :returns: BigInteger
        """

        return self.id

    @property
    def fullname_value(self):
        """Get user full name

        :returns: String
        """

        return ' '.join([x for x in (self.firstname, self.lastname) if x])

    @property
    def created_on_value(self):
        """Get user creation date in custom format

        :returns: String
        """

        return self.created_on.strftime("%Y-%m-%d %H:%M:%S %z")

    def hash_password(self, password):
        """Generate converted hash for plaintext password

        :param password: password string
        """

        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        """Validates password hash

        :param password: password string
        :returns: Boolean
        """

        return pwd_context.verify(password, self.password_hash)

    @staticmethod
    def model_fields():
        """User object fields to be shown in response

        :returns: List
        """

        return ['id', 'username', 'firstname', 'lastname',
                'address', 'contact', 'is_admin']

    @staticmethod
    def model_fields_items():
        """User object item fields to be shown in response

        :returns: List
        """

        return ['id', 'username', 'firstname', 'lastname',
                'address', 'contact', 'is_admin', 'client']


class Token(db.Model):
    """Token sqlalchemy model class"""

    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.BigInteger)
    token = db.Column(db.String(255))
    requested_on = db.Column(db.DateTime(timezone=True),
                             default=datetime.datetime.now)
    _username = None

    @property
    def username(self):
        """Get user name info

        :returns: String
        """

        return self._username

    @username.setter
    def username(self, value):
        """Set user name info

        :param value: username
        """

        self._username = value

    @property
    def requested_on_datetime(self):
        """Get token request date in custom format

        :returns: String
        """

        return self.requested_on.strftime("%Y-%m-%d %H:%M:%S %z")

    @staticmethod
    def generate(user_id):
        """Generate user authentication token

        :param user_id: user ID
        :returns: Token
        """

        user_token = Token.query.filter_by(user_id=user_id).one_or_none()
        if user_token:
            return None
        return secrets.token_urlsafe(current_app.config['BYTE_LENGTH'])

    @staticmethod
    def model_fields():
        """List of Token object fields to be shown in response

        :returns: List
        """

        return ['id', 'user_id', 'token']
