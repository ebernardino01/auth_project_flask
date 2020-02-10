import requests, json
from functools import wraps
from flask import current_app, request, jsonify, g

from api.gateway import bp
from api.error.handlers import bad_request, not_found


# Token validation decorator
def token_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        # Check the request token
        token = request.headers.get('Token')
        if token is None:
            return bad_request('Missing token')

        # Validate token
        resource = requests.get(current_app.config['API_PROTOCOL'] +
                                current_app.config['API_AUTH_HOST'] +
                                ':' +
                                current_app.config['API_AUTH_PORT'] +
                                '/api/resource',
                   headers={'Content-Type':
                            current_app.config['REST_CONTENT_TYPE'],
                            'Accept':
                            current_app.config['REST_CONTENT_TYPE'],
                            'Token': token})

        # Make user details available down the pipeline via flask.g
        g.user = json.loads(resource.text)
        if g.user is None or \
            'data' not in g.user or \
            'id' not in g.user['data'] or \
            'attributes' not in g.user['data']:
            return not_found('Invalid user token')
        return f(*args, **kwargs)
    return wrap


# Admin user validation decorator
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not g.user['data']['attributes']['is_admin']:
            return bad_request('Admin access is required')
        return f(*args, **kwargs)
    return wrap


# User registration
@bp.route('/users/new', methods=['POST'])
@current_app.validate('register', 'register')
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    address = request.json.get('address')
    contact = request.json.get('contact')
    is_admin = request.json.get('admin')

    # Submit request to auth api
    response = requests.post(current_app.config['API_PROTOCOL'] +
                             current_app.config['API_AUTH_HOST'] +
                             ':' +
                             current_app.config['API_AUTH_PORT'] +
                             '/api/users/new',
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']},
               json={'username': username,
                     'password': password,
                     'firstname': firstname,
                     'lastname': lastname,
                     'address': address,
                     'contact': contact,
                     'admin': is_admin})
    return (response.text, response.status_code)


# Custom user authentication
@bp.route('/auth', methods=['PUT'])
@current_app.validate('authenticate', 'authenticate')
def authenticate_user():
    email = request.json.get('email')
    password = request.json.get('userPassword')

    # Submit request to auth api
    response = requests.put(current_app.config['API_PROTOCOL'] +
                            current_app.config['API_AUTH_HOST'] +
                            ':' +
                            current_app.config['API_AUTH_PORT'] +
                            '/api/auth',
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']},
               json={'email': email,
                     'userPassword': password})
    return (response.text, response.status_code)


# Order placement public interface
# Requires token authentication
@bp.route('/orders/new', methods=['POST'])
@current_app.validate('order', 'order')
@token_required
def new_order():
    service = request.json.get('service')
    url = request.json.get('url')

    # Submit request to billing api
    response = requests.post(current_app.config['API_PROTOCOL'] +
                             current_app.config['API_BILL_HOST'] +
                             ':' +
                             current_app.config['API_BILL_PORT'] +
                             '/api/users/' +
                             str(g.user['data']['id']) + '/orders/new',
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']},
               json={'service': service,
                     'url': url})
    return (response.text, response.status_code)


# Retrieve list of orders for current user
# Requires token authentication
@bp.route('/orders', methods=['GET'])
@token_required
def get_order():
    # Submit request to billing api
    response = requests.get(current_app.config['API_PROTOCOL'] +
                            current_app.config['API_BILL_HOST'] +
                            ':' +
                            current_app.config['API_BILL_PORT'] +
                            '/api/users/' +
                            str(g.user['data']['id']) + '/orders',
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']})
    return (response.text, response.status_code)


# Delete/cancel order
# Requires token authentication
@bp.route('/orders/<int:order_id>', methods=['DELETE'])
@token_required
def remove_order(order_id):
    # Submit request to billing api
    response = requests.delete(current_app.config['API_PROTOCOL'] +
                               current_app.config['API_BILL_HOST'] +
                               ':' +
                               current_app.config['API_BILL_PORT'] +
                               '/api/users/' +
                               str(g.user['data']['id']) + 
                               '/orders/' + str(order_id),
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']})
    return (response.text, response.status_code)


# Approve or cancel pending order
# Requires token authentication
# Requires admin action
@bp.route('/admin/orders/<int:order_id>', methods=['PUT'])
@current_app.validate('admin', 'admin')
@token_required
@admin_required
def update_order(order_id):
    # Submit request to billing api
    action = request.json.get('action')
    response = requests.put(current_app.config['API_PROTOCOL'] +
                            current_app.config['API_BILL_HOST'] +
                            ':' +
                            current_app.config['API_BILL_PORT'] +
                            '/api/admin/orders/' + str(order_id),
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']},
               json={'action': action,
                     'approver_id': g.user['data']['id']})
    return (response.text, response.status_code)


# Retrieve pending order list
# Requires token authentication
# Requires admin action
@bp.route('/admin/orders', methods=['GET'])
@token_required
@admin_required
def get_pending_order():
    # Submit request to billing api
    response = requests.get(current_app.config['API_PROTOCOL'] +
                            current_app.config['API_BILL_HOST'] +
                            ':' +
                            current_app.config['API_BILL_PORT'] +
                            '/api/admin/orders',
               headers={'Content-Type':
                        current_app.config['REST_CONTENT_TYPE'],
                        'Accept':
                        current_app.config['REST_CONTENT_TYPE']})
    return (response.text, response.status_code)
