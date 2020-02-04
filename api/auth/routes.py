from flask import current_app, request, g

from api import db
from api.auth import bp
from api.auth.models import User, UserSchema, CustomPassAuth, \
                            CustomTokenAuth
from api.error.handlers import bad_request, duplicate


# Custom authentication objects
pwd = CustomPassAuth()
tok = CustomTokenAuth()


# Register a function to be run at the end of each request,
# regardless of whether there was an exception or not
@bp.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()


# Callback function to validate username and password
@pwd.verify_password
def verify_password():
    # Check the request arguments
    email = request.json.get('email')
    password = request.json.get('userPassword')
    if email is None or password is None:
        return False

    # Validate password
    user = User.query.filter_by(username=email).first()
    if not user or not user.verify_password(password):
        return False

    # Make user available down the pipeline via flask.g
    g.user = user
    return True


# Callback function to validate token
@tok.verify_token
def verify_token():
    # Check the request arguments
    token = request.headers.get('Token')
    if token is None:
        return False

    # Validate token
    user = User.verify_auth_token(token)
    if not user:
        return False

    # Make user available down the pipeline via flask.g
    g.user = user
    return True


# User registration
@bp.route('/api/users/new', methods=['POST'])
@current_app.validate('register', 'register')
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    is_admin = request.json.get('admin')

    # Check the request arguments
    if username is None or password is None:
        return bad_request('Missing username and/or password')

    # Check if existing user
    if User.query.filter_by(username=username).first() is not None:
        return duplicate('User already exists')

    user = User(username=username, firstname=firstname,
                lastname=lastname, is_admin=is_admin)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (UserSchema().dump(user), 201)


# Get user by id 
@bp.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    return UserSchema().dump(user)
    

# Get all users
@bp.route('/api/users', methods=['GET'])
def get_all_user():
    users = User.query.all()
    return UserSchema(many=True).dump(users)


# Custom user authentication
# Requires password authentication
# Returns token when authenticated
@bp.route('/api/auth', methods=['PUT'])
@current_app.validate('authenticate', 'authenticate')
@pwd.login_required
def authenticate_user():
    # Generate token
    token = g.user.generate_auth_token()
    return ({'token': token.decode('ascii'),
             'user': {'username': g.user.username}})


# Endpoint resource
# Requires token authentication
@bp.route('/api/resource', methods=['GET'])
@tok.login_required
def get_resource():
    return UserSchema().dump(g.user)
