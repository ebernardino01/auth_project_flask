import time
from flask import current_app
from sqlalchemy import Sequence, text
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin
)

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


OAUTH2CLIENT_ID = Sequence('oauth2client_id_seq', start=sequence)
OAUTH2AUTH_ID = Sequence('oauth2authorization_id_seq', start=sequence)
OAUTH2TOKEN_ID = Sequence('oauth2token_id_seq', start=sequence)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    """OAuth2Client sqlalchemy model class"""

    __tablename__ = 'oauth2_client'
    id = db.Column(db.BigInteger, OAUTH2CLIENT_ID, primary_key=True,
                   server_default=OAUTH2CLIENT_ID.next_value())
    user_id = db.Column(db.BigInteger)

    @property
    def client_id_issued_datetime(self):
        return time.strftime("%Y-%m-%d %H:%M:%S %z",
                             time.localtime(self.client_id_issued_at))

    @staticmethod
    def model_fields():
        """List of OAuth2Client object fields to be shown in response"""
        return ['id', 'client_id', 'client_secret',
                'client_metadata', 'user_id']


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    """OAuth2AuthorizationCode sqlalchemy model class"""

    __tablename__ = 'oauth2_code'
    id = db.Column(db.BigInteger, OAUTH2AUTH_ID, primary_key=True,
                   server_default=OAUTH2AUTH_ID.next_value())
    user_id = db.Column(db.BigInteger)

    @staticmethod
    def model_fields():
        """List of OAuth2AuthorizationCode object fields
        to be shown in response
        """
        return ['id', 'code', 'client_id', 'redirect_uri',
                'response_type', 'scope', 'user_id']


class OAuth2Token(db.Model, OAuth2TokenMixin):
    """OAuth2Token sqlalchemy model class"""

    __tablename__ = 'oauth2_token'
    id = db.Column(db.BigInteger, OAUTH2TOKEN_ID, primary_key=True,
                   server_default=OAUTH2TOKEN_ID.next_value())
    user_id = db.Column(db.BigInteger)

    @staticmethod
    def model_fields():
        """List of OAuth2Token object fields to be shown in response"""
        return ['id', 'client_id', 'token_type', 'access_token',
                'refresh_token', 'scope', 'revoked', 'user_id']

    @property
    def issued_datetime(self):
        return time.strftime("%Y-%m-%d %H:%M:%S %z",
                             time.localtime(self.issued_at))

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
