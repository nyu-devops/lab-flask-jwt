# lab-flask-jwt
This repository is part of lab for the NYU DevOps and Agile Methodologies class CSCI-GA.2810-001. It will show you how to implement JSON Web Tokens (JWT) for authentication using Python / Flask

## Key functions

Here are the key functions which can be found in `service.py` that make it all work:

### token_required()

This is the main wrapper. All work is done in this decorator function `@token_required` which can be placed before any route that you want to secure by requireing an api key be passed in the headers. It expects a JWT `Bearer` token in the `Authorization` header. It also passes the user name into the wrapped function so that user privialedges can be checked if needed.

```Python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            if token.startswith("Bearer "):
                token = token.split("Bearer ")[1]
            # Decoding the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['sub']

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated
```

### login()

This the code that looks for the existence of the user authorization and builds the JWT token that must be used on subsiquent calls.

```Python
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
```

## Test Cases

The test cases can be found in `test_service.py`. There is a helper function called `login()` in `service.py` that gets the JWT token so that the test clients can talk to the test server.

Use:

```sh
nosetests
```

To run the tests.
