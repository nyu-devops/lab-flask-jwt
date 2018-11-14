"""
 Copyright 2016, 2018 John J. Rofrano. All Rights Reserved.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
import os
import jwt
import datetime
from functools import wraps
from flask import Flask, request, Response, jsonify, abort, url_for

# Get global variables from the environment
DEBUG = (os.getenv('DEBUG', 'False') == 'True')
PORT = int(os.getenv('PORT', '5000'))
HOST = str(os.getenv('VCAP_APP_HOST', '0.0.0.0'))

# get secrets from the environment
API_USERNAME = os.getenv('API_USERNAME', None)
API_PASSWORD = os.getenv('API_PASSWORD', None)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', None)

######################################################################
# HTTP Error Handlers
######################################################################
@app.errorhandler(401)
def not_authorized(e):
    """ Sends a 401 response that enables basic auth """
    app.logger.info('Sending 401 authentication request')
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

######################################################################
# Check Auth: Add your autorization code here
######################################################################
def check_auth(auth):
    """ Checks the environment that the user is correct """
    if auth.username == API_USERNAME and auth.password == API_PASSWORD:
        return True
    return False

######################################################################
# Token Required: Decorator function to add secuity to any call
######################################################################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        #print request.headers
        if 'Authorization' in request.headers:
            bearer_token = request.headers.get('Authorization')
            if bearer_token.startswith("Bearer "):
                token = bearer_token.split("Bearer ")[1]

        if not token:
            return jsonify(message='Token is missing!'), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = data['username']
        except:
            return jsonify(message='Token is invalid!'), 401
        return f(current_user, *args, **kwargs)
    return decorated

######################################################################
# GET /
######################################################################
@app.route('/')
def index():
    """ Home page which is not protected """
    return jsonify(message='Example Flask JWT Demo',
                   url=url_for('say_hello', _external=True),
                   version='1.0'), 200

######################################################################
# GET /pets
######################################################################
@app.route('/hello', methods=['GET'])
@token_required
def say_hello(current_user):
    """ Call to get Pets which is protected by API key """
    return jsonify(hello=current_user), 200


######################################################################
# GET /login
######################################################################
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        abort(401)

    if check_auth(auth):
        payload = {
            'username': auth.username,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    abort(401)

######################################################################
#  M A I N   P R O G R A M
######################################################################
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
