from flask import (
    request,
    url_for
)
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_query_token_func,
    create_save_token_func,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import (
    grants,
    TokenEndpoint,
    UnsupportedTokenTypeError,
)
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc6749.errors import InvalidGrantError
from authlib.common.encoding import to_unicode

from authlib.oauth2.base import OAuth2Error
from api import db
from api.oauth.models import (
    OAuth2Client,
    OAuth2Token,
    OAuth2AuthorizationCode
)

from api.auth.models import User
from api.error.handlers import (
    ApiException,
    bad_request
)
from api.util.handlers import JSONAPISerializer


jsonapi_token = JSONAPISerializer(model=OAuth2Token,
                                  fields=OAuth2Token.model_fields())

jsonapi_code = JSONAPISerializer(model=OAuth2AuthorizationCode,
                                 fields=OAuth2AuthorizationCode.model_fields())


def create_oauth2_response(type):
    """Generate OAuth response details

    :param string type: 'token_detail', 'token_revoke' or \
    'authorization_code'
    """

    # print("[POST] request: {}".format(str(request)))
    request_data = request.json.get('data')
    if request_data is None or 'attributes' not in request_data:
        return bad_request('Invalid request object')

    # Create request object and schema
    request_body = request_data.get('attributes')
    url = request.base_url
    if request.query_string:
        url = url + '?' + to_unicode(request.query_string)
    oauth2request = OAuth2Request(request.method,
                                  url,
                                  request_body,
                                  request.headers)

    # Obtain and validate grant from request
    if type != 'token_revoke':
        try:
            if type == 'token_detail':
                grant = authorization.get_token_grant(oauth2request)
            elif type == 'authorization_code':
                grant = authorization.get_authorization_grant(oauth2request)
        except InvalidGrantError as error:
            return authorization.handle_error_response(oauth2request, error)

    # Validate request and return JSONAPI token response
    try:
        if type == 'token_detail':
            grant.validate_token_request(request_body)
            response_args = grant.create_token_response()
            # print("[POST] response_args: {}".format(str(response_args)))

            result = response_args[1]
            # print("[POST] result: {}".format(str(result)))

            response_json_headers = [
                ('Content-Type', 'application/vnd.api+json'),
                ('Location', url_for('oauth.get_token'))
            ]

            status_code = 201
        elif type == 'token_revoke':
            endpoint = authorization.get_endpoint('revocation')
            result = jsonapi_token.serialize(endpoint(oauth2request),
                                             url_for('oauth.revoke_token'))
            # print("[POST] result: {}".format(str(result)))

            response_json_headers = [
                ('Content-Type', 'application/vnd.api+json')
            ]

            status_code = 200
        elif type == 'authorization_code':
            username = request_body.get('username')
            grant_user = User.query.filter_by(username=username).first()
            redirect_uri = grant.validate_authorization_request()
            response_args = grant.create_authorization_response(redirect_uri,
                                                                grant_user)
            # print("[POST] response_args: {}".format(str(response_args)))

            result = jsonapi_code.serialize(response_args[1], '')
            # print("[POST] result: {}".format(str(result)))

            status_code = response_args[0]
            response_json_headers = response_args[2]

        return authorization.handle_response(status_code,
                                             result,
                                             response_json_headers)
    except OAuth2Error as error:
        return authorization.handle_error_response(oauth2request, error)
    except ApiException as exception:
        return exception.error_response()


def authenticate_oauth2_client(client_id, client_secret, grant):
    """Validate client flow

    1. Get client_id from request data
    2. Validate client_id if exists
    3. Validate token endpoint authentication method
       a. If method = 'client_secret_basic'
          -> Get client_secret from request data
          -> Validate client_secret if match
       b. If method = 'none'
          -> Check client_secret from request data if blank

    :param string client_id: client ID
    :param string client_secret: client password
    """

    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if client is None:
        raise ApiException('Client not found',
                           status_code=404)

    AUTH_METHODS = ['client_secret_basic', 'none']
    if client.token_endpoint_auth_method in AUTH_METHODS and not \
       client.check_client_secret(client_secret):
        raise ApiException('Client authentication failed',
                           status_code=401)

    # Send authenticate client signal to framework
    # print("[authenticate_oauth2_client] client: {}".format(str(client)))
    if grant:
        grant.server.send_signal('after_authenticate_client',
                                 client=client, grant=grant)

        # Validate client grant type
        if not client.check_grant_type(grant.GRANT_TYPE):
            raise ApiException('Client is not authorized',
                               status_code=401)

    return client


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """AuthorizationCodeGrant class extension from authlib"""

    '''
    def create_authorization_code(self, client, grant_user, request):
        # code = gen_salt(48)
        code = secrets.token_urlsafe(
            current_app.config['BYTE_LENGTH_SECRET'])
        item = OAuth2AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            user_id=grant_user.id,
        )
        db.session.add(item)
        db.session.commit()
        return code

    def parse_authorization_code(self, code, client):
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item
    '''

    def save_authorization_code(self, code, request):
        if OAuth2AuthorizationCode.query.filter_by(
           client_id=request.client.client_id).first():
            raise ApiException('Authorization code already exists for client',
                               status_code=409)

        code_challenge = request.data.get('code_challenge')
        if not code_challenge:
            raise ApiException('Missing code_challenge in request',
                               status_code=400)
        code_challenge_method = request.data.get(
            'code_challenge_method', 'S256')

        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            response_type=request.response_type,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)

    def validate_token_request(self, request_body):
        client = authenticate_oauth2_client(
            self.request.client_id,
            self.request.body.get('client_secret'),
            self
        )

        '''
        # Send authenticate client signal to framework
        # print("[AuthorizationCodeGrant] client: {}".format(str(client)))
        self.server.send_signal('after_authenticate_client',
                                client=client, grant=self)
        '''

        # print("[AuthorizationCodeGrant] client: {}".format(str(client)))
        code = self.request.body.get('code')
        if not code:
            raise ApiException('Missing code in request',
                               status_code=400)

        code_verifier = self.request.body.get('code_verifier')
        if not code_verifier:
            raise ApiException('Missing code_verifier in request',
                               status_code=400)

        # Ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = self.query_authorization_code(code, client)
        if not authorization_code:
            raise ApiException('Invalid code in request',
                               status_code=400)

        # Validate code challenge
        # print("[AuthorizationCodeGrant] code challenge: {}".format(
        #     str(authorization_code.code_challenge)))
        '''
        code_challenge = code_verifier \
            if code_challenge_method is not 'S256' \
            else create_s256_code_challenge(code_verifier)

        if code_challenge == authorization_code.code_challenge:
            raise ApiException('Mismatch code_verifier in request',
                               status_code=400)
        '''

        # Validate redirect_uri parameter
        redirect_uri = self.request.redirect_uri
        original_redirect_uri = authorization_code.get_redirect_uri()
        if original_redirect_uri and redirect_uri != original_redirect_uri:
            raise ApiException('Invalid redirect_uri in request',
                               status_code=400)

        self.request.client = client
        self.request.credential = authorization_code
        self.execute_hook('after_validate_token_request')


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    """ResourceOwnerPasswordCredentialsGrant class extension from authlib"""

    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user is not None and user.verify_password(password):
            return user

    def validate_token_request(self, request_body):
        # print("[PasswordGrant] request: {}".format(str(self.request)))
        client = authenticate_oauth2_client(self.request.client_id,
                                            self.request.body['client_secret'],
                                            self)

        '''
        # Send authenticate client signal to framework
        # print("[PasswordGrant] client: {}".format(str(client)))
        self.server.send_signal('after_authenticate_client',
                                client=client, grant=self)

        # Validate client grant type
        if not client.check_grant_type(self.GRANT_TYPE):
            raise ApiException('Client is not authorized',
                               status_code=401)
        '''

        # Validate user credentials
        # print("[PasswordGrant] client: {}".format(str(client)))
        user = self.authenticate_user(self.request.body['username'],
                                      self.request.body['password'])
        if not user:
            raise ApiException('Invalid username or password in request',
                               status_code=400)

        self.request.client = client
        self.request.user = user
        self.validate_requested_scope()


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    """ClientCredentialsGrant class extension from authlib"""

    def validate_token_request(self, request_body):
        client = authenticate_oauth2_client(self.request.client_id,
                                            self.request.body['client_secret'],
                                            self)

        '''
        # Send authenticate client signal to framework
        # print("[ClientCredentialsGrant] client: {}".format(str(client)))
        self.server.send_signal('after_authenticate_client',
                                client=client, grant=self)

        # Validate client grant type
        if not client.check_grant_type(self.GRANT_TYPE):
            raise ApiException('Client is not authorized',
                               status_code=401)
        '''

        # print("[ClientCredentialsGrant] client: {}".format(str(client)))
        self.request.client = client
        self.validate_requested_scope()


class ImplicitGrant(grants.ImplicitGrant):
    """ImplicitGrant class extension from authlib"""

    def validate_authorization_request(self):
        # print("[ImplicitGrant] client: {}".format(self.request))
        client = authenticate_oauth2_client(self.request.client_id, '', self)

        '''
        # Send authenticate client signal to framework
        # print("[ImplicitGrant] client: {}".format(str(client)))
        self.server.send_signal('after_authenticate_client',
                                client=client, grant=self)
        '''

        # Validate redirect uri
        # print("[ImplicitGrant] client: {}".format(str(client)))
        redirect_uri = self.validate_authorization_redirect_uri(
            self.request, client)

        # Validate client response type
        response_type = self.request.response_type
        if not client.check_response_type(response_type):
            raise ApiException(
                'The client is not authorized to use '
                '"response_type={}"'.format(response_type),
                status_code=401
            )

        try:
            self.request.client = client
            self.validate_requested_scope()
            self.execute_hook('after_validate_authorization_request')
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            error.redirect_fragment = True
            raise error
        return redirect_uri


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """RefreshTokenGrant class extension from authlib"""

    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(
            refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()

    def validate_token_request(self, request_body):
        client = authenticate_oauth2_client(self.request.client_id,
                                            self.request.body['client_secret'],
                                            self)

        '''
        # Send authenticate client signal to framework
        # print("[RefreshTokenGrant] client: {}".format(str(client)))
        self.server.send_signal('after_authenticate_client',
                                client=client, grant=self)

        # Validate client grant type
        if not client.check_grant_type(self.GRANT_TYPE):
            raise ApiException('Client is not authorized',
                               status_code=401)
        '''

        # Validate refresh token
        # print("[RefreshTokenGrant] client: {}".format(str(client)))
        refresh_token = self.request.body['refresh_token']
        if refresh_token is None:
            raise ApiException('Missing refresh_token in request',
                               status_code=400)

        token = self.authenticate_refresh_token(refresh_token)
        if not token or token.get_client_id() != client.get_client_id():
            raise ApiException('Invalid refresh_token in request',
                               status_code=400)

        self.request.client = client
        self._validate_token_scope(token)
        self.request.credential = token


class OAuth2AuthorizationServer(AuthorizationServer):
    def get_endpoint(self, name):
        return self._endpoints[name]


class OAuth2RevocationEndpoint(TokenEndpoint):
    """Custom implementation of revocation endpoint class
    defined in authlib to fit with JSONAPI
    """

    ENDPOINT_NAME = 'revocation'

    def authenticate_endpoint_credential(self, data, client):
        if 'token' not in data or \
           'token_type_hint' not in data:
            raise ApiException('Invalid token or token type in request',
                               status_code=400)

        token_type = data.get('token_type_hint')
        if token_type and token_type not in self.SUPPORTED_TOKEN_TYPES:
            raise UnsupportedTokenTypeError()
        return self.query_token(data.get('token'), token_type, client)

    def create_endpoint_response(self, request):
        # The authorization server first validates the client credentials
        client = authenticate_oauth2_client(request.body.get('client_id'),
                                            request.body.get('client_secret'),
                                            None)

        # Verify whether the token was issued to the client making
        # the revocation request
        credential = self.authenticate_endpoint_credential(request.body,
                                                           client)

        # Authorization server invalidates the token
        # print("[create_endpoint_response] credential: {}".format(
        #     str(credential)))
        if not credential:
            raise ApiException('Token or token type in request is not found',
                               status_code=404)

        self.revoke_token(credential)
        self.server.send_signal(
            'after_revoke_token',
            token=credential,
            client=client,
        )
        return credential


def create_oauth2_revocation_endpoint(session, token_model):
    """Customized implementation of create revocation endpoint class
    defined in authlib to fit with flask-rest-jsonapi
    """

    query_token = create_query_token_func(session, token_model)

    class _OAuth2RevocationEndpoint(OAuth2RevocationEndpoint):
        def query_token(self, token, token_type_hint, client):
            return query_token(token, token_type_hint, client)

        def revoke_token(self, token):
            token.revoked = True
            session.add(token)
            session.commit()

    return _OAuth2RevocationEndpoint


query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token)
authorization = OAuth2AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()


def config_oauth(app):
    """OAuth configuration factory

    :param object app: Flask application object
    """

    # Initialize OAuth
    authorization.init_app(app)

    # Support grants
    authorization.register_grant(ImplicitGrant)
    authorization.register_grant(ClientCredentialsGrant)
    authorization.register_grant(AuthorizationCodeGrant,
                                 [CodeChallenge(required=True)])
    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)

    # Support revocation
    revocation_cls = create_oauth2_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # Protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
