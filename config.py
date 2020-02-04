import os

# Configuration class
class Config(object):
    # authentication
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'this app uses flask'
    TOKEN_TIME = 800

    # sqlalchemy
    SQLALCHEMY_DATABASE_URI = 'postgresql:///psqlappdb'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # json schema
    JSONSCHEMA_ROOT = 'schemas'

    # route url 
    API_PROTOCOL = 'http://'
    API_AUTH_HOST = 'localhost'
    API_AUTH_PORT = '5001'
    API_BILL_HOST = 'localhost'
    API_BILL_PORT = '5002'
    
    # rest api
    REST_CONTENT_TYPE = 'application/json'
