"""
 Copyright 2016, 2024 John J. Rofrano. All Rights Reserved.

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
import status
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, make_response, jsonify, abort, url_for

# Get global variables from the environment
DEBUG = os.getenv('DEBUG', 'False') == 'True'
PORT = int(os.getenv('PORT', '5000'))
HOST = str(os.getenv('HOST', '0.0.0.0'))

# get secrets from the environment
API_USERNAME = os.getenv('API_USERNAME')
API_PASSWORD = os.getenv('API_PASSWORD')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

######################################################################
# HTTP Error Handlers
######################################################################
@app.errorhandler(status.HTTP_401_NOT_AUTHORIZED)
def not_authorized(error):
    """ Sends a 401 response that enables basic auth """
    message = str(error)
    app.logger.warning("401 Unauthorized: %s", message)
    return make_response(
        jsonify(
            status=status.HTTP_401_NOT_AUTHORIZED, 
            error="Could not verify your credentials for that URL.", 
            message=message
        ),
        status.HTTP_401_NOT_AUTHORIZED,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


######################################################################
# Check Auth: Add your authorization code here
######################################################################
def check_auth(auth):
    """ Checks the environment that the user is correct """
    if auth.username == API_USERNAME and auth.password == API_PASSWORD:
        return True
    return False

######################################################################
# Token Required: Decorator function to add security to any call
######################################################################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), status.HTTP_401_NOT_AUTHORIZED

        try:
            if token.startswith("Bearer "):
                token = token.split("Bearer ")[1]
            # Decoding the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['sub']

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), status.HTTP_401_NOT_AUTHORIZED
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), status.HTTP_401_NOT_AUTHORIZED

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
                   version='1.0'), status.HTTP_200_OK

######################################################################
# GET /pets
######################################################################
@app.route('/hello', methods=['GET'])
@token_required
def say_hello(current_user):
    """ Call to get Pets which is protected by API key """
    return jsonify(hello=current_user), status.HTTP_200_OK


######################################################################
# GET /login
######################################################################
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        abort(status.HTTP_401_NOT_AUTHORIZED)

    if check_auth(auth):
        payload = {
            'sub': auth.username,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=60)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})

    abort(status.HTTP_401_NOT_AUTHORIZED)


######################################################################
#  M A I N   P R O G R A M
######################################################################
if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
