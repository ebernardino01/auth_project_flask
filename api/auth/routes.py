"""api/auth/routes.py"""

import secrets
from json import loads, dumps
from sqlalchemy import func
from flask import (
    current_app,
    request,
    g,
    url_for
)

from api import db, executor, redis_client
from api.auth import bp
from api.auth.auth import pwd, tok
from api.auth.models import (
    User,
    Token
)
from api.error.handlers import (
    ApiException,
    bad_request,
    duplicate
)
from api.util.handlers import (
    create_query_conditions,
    JSONAPISerializer,
    jsonapi_headers
)

from api.oauth.models import OAuth2Client


@bp.teardown_request
def teardown_request(exception):
    """Register a function to be run at the end of each request,
    regardless of whether there was an exception or not

    """

    if exception:
        db.session.rollback()
    db.session.remove()


def get_user_count():
    """Query the user count"""

    # print("get_user_count thread")
    return db.session.query(func.count(User.id))


def get_user_detail(user_id):
    """Query the user detail"""

    # print("get_user_detail thread")
    return db.session.query(User).get(user_id)


def get_user_client(user_id):
    """Query the user client detail"""

    # print("get_user_client thread")
    return db.session.query(OAuth2Client).filter(
        User.id == user_id).all()


def get_users_from_query(query):
    """Query all users"""

    return query.all()


def reset_redis_cache():
    """Reset redis cache values"""

    for key in redis_client.hkeys('USER_LIST_HASH'):
        redis_client.hdel('USER_LIST_HASH', key)

    for key in redis_client.hkeys('USER_ITEM_HASH'):
        redis_client.hdel('USER_ITEM_HASH', key)


# Initialize JSONAPI serializers for API response
jsonapi_user = JSONAPISerializer(model=User,
                                 fields=User.model_fields())

jsonapi_token = JSONAPISerializer(model=Token,
                                  fields=Token.model_fields())

jsonapi_user_item = JSONAPISerializer(model=User,
                                      fields=User.model_fields_items())

jsonapi_client = JSONAPISerializer(model=OAuth2Client,
                                   fields=OAuth2Client.model_fields())


@bp.route('/users', methods=['POST'])
@current_app.validate('user', 'user')
def new_user():
    """New user registration

    .. :quickref: User; Create new user

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "users",
    "attributes": {"username":"","password":"","firstname":"",
    "lastname":"","address":"","contact":"","is_admin":""}}}'
    -i -X POST http://127.0.0.1:5000/api/users``

    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string username: username (REQUIRED)
    :<json string password: plaintext password (REQUIRED)
    :<json string firstname: firstname
    :<json string lastname: lastname
    :<json string address: address
    :<json string contact: contact
    :<json Boolean is_admin: defaults to False if not specified
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant created user details
    :resheader Content-Type: application/vnd.api+json
    :status 201: post created
    :status 400: malformed request
    :status 409: duplicate username
    |
    """

    # Check the request data arguments
    info = request.json.get('data')
    if info is None or 'attributes' not in info:
        return bad_request('Invalid request details')

    username = info['attributes'].get('username')
    password = info['attributes'].get('password')
    firstname = info['attributes'].get('firstname', '')
    lastname = info['attributes'].get('lastname', '')
    address = info['attributes'].get('address', '')
    contact = info['attributes'].get('contact', '')
    is_admin = info['attributes'].get('is_admin')
    # add_info = info['attributes'].get('info', '')

    # Check the request arguments
    if username is None or password is None:
        return bad_request('Missing username and/or password')

    # Check if existing user
    if User.query.filter(User.username == username).first() is not None:
        return duplicate('User already exists')

    user = User(username=username, firstname=firstname,
                lastname=lastname, address=address,
                contact=contact, is_admin=is_admin)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()

    reset_redis_cache()
    return (jsonapi_user.serialize(user,
                                   url_for('auth.new_user',
                                           _external=True)),
            201,
            jsonapi_headers)


@bp.route('/users', methods=['GET'])
def get_all_user():
    """Get all users

    .. :quickref: User; Get list of all users

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/users``

    :query filter: filtering criteria e.g. ``filter[username]=user``
    :query sort: sorting order e.g. ``sort=username,-firstname``
    :query page: pagination details e.g. ``page[size]=2&page[number]=1``
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant list of all users
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    :status 400: malformed request
    |
    """

    response = redis_client.hget('USER_LIST_HASH', 'ALL')
    if response is not None:
        # print("[get_all_user] decode: {}".format(response.decode()))
        return loads(response.decode())

    count_future = executor.submit(get_user_count)
    if request.args:
        try:
            query = create_query_conditions(db.session.query(User),
                                            User, request.args)

            users_future = executor.submit(get_users_from_query, query)
        except ApiException as exception:
            return bad_request(exception.message)
    else:
        users_future = executor.submit(get_users_from_query,
                                       db.session.query(User))

    result = jsonapi_user.serialize(users_future.result(),
                                    url_for('auth.get_all_user',
                                            _external=True),
                                    request.args,
                                    count_future.result())

    # Set redis cache value
    if not request.args:
        redis_client.hsetnx('USER_LIST_HASH', 'ALL', str(dumps(result)))
    return (result, 200, jsonapi_headers)


@bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get user details by id

    .. :quickref: User; Get user details

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/users/{user_id}``

    :param id: user ID
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant details of user
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    |
    """

    response = redis_client.hget('USER_LIST_HASH', user_id)
    # print("[get_user] redis get response: {}".format(str(response)))

    if response is not None:
        # print("[get_user] decode: {}".format(response.decode()))
        return loads(response.decode())

    user = get_user_detail(user_id)
    result = jsonapi_user.serialize(user,
                                    url_for('auth.get_user',
                                            _external=True,
                                            id=user_id))

    # Set redis cache value
    redis_client.hsetnx('USER_LIST_HASH',
                        str(user_id),
                        str(dumps(result)))

    return (result, 200, jsonapi_headers)


@bp.route('/auth', methods=['POST'])
@current_app.validate('token', 'token')
@pwd.login_required
def get_token():
    """Custom user authentication

    .. :quickref: Token; Generate user token

    **CURL command:**

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -d '{"data": {"type": "tokens",
    "attributes": {"email":"","userPassword":""}}}'
    -X POST http://127.0.0.1:5000/api/auth``

    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :<json string email: username (REQUIRED)
    :<json string userPassword: plaintext password (REQUIRED)
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant created token details
    :resheader Content-Type: application/vnd.api+json
    :status 201: post created
    |
    """

    token = Token(
        user_id=g.user.id,
        username=g.user.username,
        token=secrets.token_urlsafe(current_app.config['BYTE_LENGTH'])
    )
    db.session.add(token)
    db.session.commit()
    return (jsonapi_token.serialize(token,
                                    url_for('auth.get_token',
                                            _external=True)),
            201,
            jsonapi_headers)


@bp.route('/users/<int:user_id>/items', methods=['GET'])
@tok.login_required
def get_user_items(user_id):
    """User related items

    .. :quickref: User; Get user related items

    ``curl -H 'Accept: application/json' -H 'Content-Type: application/json'
    -i -X GET http://127.0.0.1:5000/api/users/{user_id}/items``

    :param id: user ID
    :reqheader Accept: application/json
    :reqheader Content-Type: application/json
    :returns: `JSON:API <http://jsonapi.org>`_\
    compliant list of items of requesting user
    :resheader Content-Type: application/vnd.api+json
    :status 200: OK
    |
    """

    # user_future = executor.submit(get_user_detail, user_id)
    client_future = executor.submit(get_user_client, user_id)

    # user = user_future.result()
    user = get_user_detail(user_id)
    user.client = jsonapi_client.serialize(
        client_future.result(), ''
    )

    result = jsonapi_user_item.serialize(user,
                                         url_for('auth.get_user_items',
                                                 _external=True,
                                                 id=user_id))

    redis_client.hsetnx('USER_ITEM_HASH',
                        str(user_id),
                        str(dumps(result)))

    return (result, 200, jsonapi_headers)


@bp.route('/resource', methods=['GET'])
@tok.login_required
def get_resource():
    """Endpoint resource"""

    return (jsonapi_user.serialize(g.user,
                                   url_for('auth.get_resource',
                                           _external=True)),
            200,
            jsonapi_headers)
