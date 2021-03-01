import time
import secrets
from json import loads, dumps
from sqlalchemy import func
from flask import (
    request,
    current_app,
    url_for
)
from werkzeug.security import gen_salt
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from api import db, executor, redis_client
from api.oauth import bp
from api.oauth.models import OAuth2Client
from api.oauth.oauth2 import create_oauth2_response

from api.error.handlers import (
    ApiException,
    bad_request,
    not_found
)
from api.util.handlers import (
    split_by_separator,
    create_query_conditions,
    JSONAPISerializer,
    jsonapi_headers
)


def get_client_count():
    # print("get_client_count thread")
    return db.session.query(func.count(OAuth2Client.id))


def get_client_count_by_id(user_id):
    # print("get_client_count_by_id thread")
    return db.session.query(func.count(OAuth2Client.id)).filter(
        OAuth2Client.user_id == user_id)


def get_clients_from_query(query):
    return query.all()


def reset_redis_cache():
    # Reset redis cache values
    for key in redis_client.hkeys('OAUTH2_CLIENT_LIST_HASH'):
        redis_client.hdel('OAUTH2_CLIENT_LIST_HASH', key)

    for key in redis_client.hkeys('OAUTH2_CLIENT_DETAIL_HASH'):
        redis_client.hdel('OAUTH2_CLIENT_DETAIL_HASH', key)


# Initialize JSONAPI serializer for API response
jsonapi_client = JSONAPISerializer(
    model=OAuth2Client,
    fields=OAuth2Client.model_fields()
)


@bp.route('/oauth/users/<int:user_id>/clients', methods=['POST'])
@current_app.validate('file', 'file')
def new_client(user_id):
    """Register new oauth client

    .. :quickref: OAuth; Register new oauth client

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "oauth2client", "attributes":
    {"client_name":"", "client_uri":"",
    "scope":"", "grant_types":"",
    "redirect_uris":"", "response_types":"",
    "token_endpoint_auth_method":""}}}'
    -i -X POST http://127.0.0.1:5000/api/oauth/users/{user_id}/clients``

    :param user_id: user ID of resource owner
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string client_name: client name
    :<json string client_uri: client URI information
    :<json string scope: authorization scope
    :<json string grant_types: 'authorization_code', 'password', \
    'client_credentials', 'implicit' or 'refresh_token'
    :<json string redirect_uris: redirection URI information
    :<json string response_types: 'token' or 'code'
    :<json string token_endpoint_auth_method: 'client_secret_basic' or 'none'
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant created oauth client details
    :resheader Content-Type: application/vnd.api+json
    :status 201: post created
    :status 400: malformed request
    |
    """

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user_id,
    )

    info = request.json.get('data')
    if info is None or 'attributes' not in info:
        return bad_request('Invalid request details')

    client_metadata = {
        'client_name': info['attributes'].get('client_name', ''),
        'client_uri': info['attributes'].get('client_uri', ''),
        'grant_types':
            split_by_separator(info['attributes'].get('grant_types', '')),
        'redirect_uris':
            split_by_separator(info['attributes'].get('redirect_uris', '')),
        'response_types':
            split_by_separator(info['attributes'].get('response_types', '')),
        'scope': info['attributes'].get('scope', ''),
        'token_endpoint_auth_method':
            info['attributes'].get('token_endpoint_auth_method', '')
    }

    client.set_client_metadata(client_metadata)
    client.client_secret = '' if client.token_endpoint_auth_method == 'none' \
        else gen_salt(48)
    # print("client secret: {}".format(client.client_secret))

    db.session.add(client)
    db.session.commit()

    reset_redis_cache()
    return (jsonapi_client.serialize(client,
                                     url_for('oauth.new_client',
                                             _external=True,
                                             user_id=user_id)),
            201,
            jsonapi_headers)


@bp.route('/oauth/clients', methods=['GET'])
def get_all_client():
    """Get all oauth client

    .. :quickref: OAuth; Get list of all oauth clients

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/oauth/clients``

    :query filter: filtering criteria e.g. ``filter[id]=1000001``
    :query sort: sorting order e.g. ``sort=id,-client_id``
    :query page: pagination details e.g. ``page[size]=2&page[number]=1``
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant list of all oauth clients
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    :status 400: malformed request
    |
    """

    response = redis_client.hget('OAUTH2_CLIENT_LIST_HASH', 'ALL')
    if response is not None:
        # print("[get_all_client] decode: {}".format(response.decode()))
        return loads(response.decode())

    count_future = executor.submit(get_client_count)
    if request.args:
        try:
            query = create_query_conditions(db.session.query(OAuth2Client),
                                            OAuth2Client, request.args)

            clients_future = executor.submit(get_clients_from_query, query)
        except ApiException as exception:
            return bad_request(exception.message)
    else:
        clients_future = executor.submit(get_clients_from_query,
                                         db.session.query(OAuth2Client))

    result = jsonapi_client.serialize(clients_future.result(),
                                      url_for('oauth.get_all_client',
                                              _external=True),
                                      request.args,
                                      count_future.result())

    if not request.args:
        redis_client.hsetnx('OAUTH2_CLIENT_LIST_HASH',
                            'ALL', str(dumps(result)))

    return (result, 200, jsonapi_headers)


@bp.route('/oauth/users/<int:user_id>/clients', methods=['GET'])
def get_client_list(user_id):
    """Get user registered oauth client

    .. :quickref: OAuth; Get list of user registered oauth clients

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/oauth/users/{user_id}/clients``

    :param user_id: user ID of resource owner
    :query filter: filtering criteria e.g. ``filter[id]=1000001``
    :query sort: sorting order e.g. ``sort=id,-client_id``
    :query page: pagination details e.g. ``page[size]=2&page[number]=1``
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant list of user registered oauth clients
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    :status 400: malformed request
    |
    """

    response = redis_client.hget('OAUTH2_CLIENT_LIST_HASH', user_id)
    if response is not None:
        # print("[get_client_list] decode: {}".format(response.decode()))
        return loads(response.decode())

    count_future = executor.submit(get_client_count_by_id, user_id)
    if request.args:
        try:
            query = create_query_conditions(
                db.session.query(OAuth2Client).filter(
                    OAuth2Client.user_id == user_id),
                OAuth2Client, request.args)

            clients_future = executor.submit(get_clients_from_query, query)
        except ApiException as exception:
            return bad_request(exception.message)
    else:
        clients_future = executor.submit(get_clients_from_query,
                                         db.session.query(OAuth2Client).filter(
                                             OAuth2Client.user_id == user_id))

    result = jsonapi_client.serialize(clients_future.result(),
                                      url_for('oauth.get_client_list',
                                              _external=True,
                                              user_id=user_id),
                                      request.args,
                                      count_future.result())

    if not request.args:
        redis_client.hsetnx('OAUTH2_CLIENT_LIST_HASH',
                            str(user_id),
                            str(dumps(result)))

    return (result, 200, jsonapi_headers)


@bp.route('/oauth/users/<int:user_id>/clients/<int:id>',
          methods=['GET'])
def get_client(user_id, id):
    """Get oauth client detail

    .. :quickref: OAuth; Get oauth client detail

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/oauth/users/{user_id}/clients/{id}``

    :param user_id: user ID of resource owner
    :param id: client ID
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant details of oauth client
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    |
    """

    response = redis_client.hget('OAUTH2_CLIENT_DETAIL_HASH', id)
    if response is not None:
        # print("[get_client] decode: {}".format(response.decode()))
        return loads(response.decode())

    client = OAuth2Client.query.filter(
        OAuth2Client.id == id,
        OAuth2Client.user_id == user_id).one_or_none()

    result = jsonapi_client.serialize(client,
                                      url_for('oauth.get_client',
                                              _external=True,
                                              id=id,
                                              user_id=user_id))

    redis_client.hsetnx('OAUTH2_CLIENT_DETAIL_HASH',
                        str(id),
                        str(dumps(result)))

    return (result, 200, jsonapi_headers)


@bp.route('/oauth/users/<int:user_id>/clients/<int:id>',
          methods=['DELETE'])
def remove_client(user_id, id):
    """Delete oauth client by id

    .. :quickref: OAuth; Delete oauth client

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X DELETE http://127.0.0.1:5000/api/oauth/users/{user_id}/clients/{id}``

    :param user_id: user ID of resource owner
    :param id: client ID
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant updated list of all oauth clients
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    :status 404: specified client not found
    |
    """

    # Filter by client id, user id
    client = OAuth2Client.query.filter(
        OAuth2Client.id == id,
        OAuth2Client.user_id == user_id).one_or_none()

    if not client:
        return not_found('Client not found')

    # Delete client
    db.session.delete(client)
    db.session.commit()
    clients = OAuth2Client.query.filter(
        OAuth2Client.user_id == user_id).all()

    reset_redis_cache()
    return (jsonapi_client.serialize(clients,
                                     url_for('oauth.get_all_client',
                                             _external=True)),
            200,
            jsonapi_headers)


@bp.route('/oauth/clients/authorize', methods=['POST'])
def get_authorization_code():
    """Get oauth client authorization code

    .. :quickref: OAuth; Get client authorization code

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "oauth2code", "attributes":
    {"username":"","response_type":"",
    "client_id":"","redirect_uri":""}}}'
    -i -X POST http://127.0.0.1:5000/api/oauth/clients/authorize``

    :param user_id: user ID of resource owner
    :param id: client ID
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string client_id: client ID
    :<json string username: resource owner related to client
    :<json string response_type: 'code' or 'token'
    :<json string redirect_uri: redirection URI information
    :returns: Authorization code or token details in location URL
    :resheader Content-Type: application/vnd.api+json
    :resheader Location: redirection link with authorization code
    :status 302: redirect URL including the authorization code \
    (response_type = 'code') or access token details \
    (response_type = 'token')
    |
    """

    return create_oauth2_response('authorization_code')


@bp.route('/oauth/token', methods=['POST'])
def get_token():
    """Get oauth client token

    .. :quickref: OAuth; Get client token

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "oauth2token", "attributes":
    {"client_id":"","client_secret":"","grant_type":"","scope":"",
    "code":"","redirect_uri":"","refresh_token":"",
    "username":"","password":""}}}'
    -i -X POST http://127.0.0.1:5000/api/oauth/token``

    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string client_id: client ID
    :<json string client_secret: client password
    :<json string grant_type: 'authorization_code', 'password', \
    'client_credentials' or 'refresh_token'
    :<json string scope: authorization scope
    :<json string username: resource owner username \
    (required only when grant type is 'password')
    :<json string password: resource owner password \
    (required only when grant type is 'password')
    :<json string code: authorization code \
    (required only when grant type is 'authorization_code')
    :<json string redirect_uri: redirection URI \
    (required only when grant type is 'authorization_code')
    :<json string refresh_token: refresh token \
    (required only when grant type is 'refresh_token')
    :returns: OAuth 2.0 client token details
    :resheader Content-Type: application/vnd.api+json
    :resheader Location: post url
    :status 201: post created
    :status 400: malformed request
    :status 401: invalid credentials
    |
    """

    return create_oauth2_response('token_detail')


@bp.route('/oauth/token/revoke', methods=['POST'])
def revoke_token():
    """Revoke oauth client token

    .. :quickref: OAuth; Revoke client token

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "oauth2tokenrevoke", "attributes":
    {"client_id":"","client_secret":"","token":"","token_type_hint":""}}}'
    -i -X POST http://127.0.0.1:5000/api/oauth/token/revoke``

    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string client_id: client ID
    :<json string client_secret: client password
    :<json string token: authorization token
    :<json string token_type_hint: 'access_token' or 'refresh_token'
    :returns: OAuth 2.0 updated client token details
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    |
    """

    return create_oauth2_response('token_revoke')


@bp.route('/oauth/clients/challenge', methods=['GET'])
def get_code_verifier():
    """Get oauth client code challenge and verifier

    .. :quickref: OAuth; Get code challenge and verifier

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/oauth/clients/challenge``

    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: Client code challenge to be used for requesting authorization \
    and code verifier for requesting access token
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    |
    """

    serialized = {
        'jsonapi': {
            'version': '1.0'
        }
    }
    top_level = {
        'type': 'oauth2code'
    }

    # Generate code verifier and code challenge for client
    code_verifier = secrets.token_urlsafe(
        current_app.config['BYTE_LENGTH_SECRET'])

    top_level['attributes'] = \
        {"code_verifier": code_verifier,
         "code_challenge": {"plain": code_verifier,
                            "S256": create_s256_code_challenge(code_verifier)}
         }
    serialized['data'] = {}
    serialized['data'] = top_level
    serialized['meta'] = {'count': 1}
    serialized['links'] = url_for('oauth.get_code_verifier',
                                  _external=True)

    return (serialized, 200, jsonapi_headers)
