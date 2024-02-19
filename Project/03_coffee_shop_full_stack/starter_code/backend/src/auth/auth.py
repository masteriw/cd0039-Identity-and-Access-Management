import json
import pprint
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen
import logging

AUTH0_DOMAIN = 'masteriw.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'TestApi'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
'''
This function is used to get the access token from the authorization header of the HTTP request. 
It checks if the authorization header is present and if the authorization scheme is "Bearer". 
Then, it returns the access token.
'''
def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        logging.debug('Authorization header missing')
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        logging.debug('Invalid header: Authorization header must start with "Bearer"')
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        logging.debug('Invalid header: Token not found')
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        logging.debug('Invalid header: Authorization header must be bearer token')
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    logging.debug('Token obtained from Authorization header')
    return token

'''
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
# The check_permissions function checks if a specific permission is present in the payload.
def check_permissions(permission, payload):
    # Checks if the 'permissions' key is present in the payload.
    # If it's not, an AuthError exception is raised with a specific error message.
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    # Checks if the specific permission is present in the payload's permissions list.
    # If it's not, an AuthError exception is raised with a specific error message.
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)


'''
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
'''
This function is used to verify and decode the JWT (JSON Web Token). 
It fetches the public keys from your Auth0 domain, checks if the JWT 
has a "kid" in the header, and then uses the appropriate key to 
decode the JWT. It also checks if the JWT has not expired and if the 
claims are correct.
'''
def verify_decode_jwt(token):
    # Fetch the JSON Web Key Set (JWKS) from the Auth0 domain
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Get the unverified header of the JWT
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}

    # Check if the 'kid' key is in the unverified header
    if 'kid' not in unverified_header:
        logging.debug('Key ID not in unverified header')
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    # Loop through the keys in the JWKS
    for key in jwks['keys']:
        # If the 'kid' of the current key matches the 'kid' in the unverified header
        if key['kid'] == unverified_header['kid']:
            # Build the RSA key
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    # If the RSA key was found
    if rsa_key:
        try:
            # Decode the JWT using the RSA key
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            # Return the payload of the JWT
            return payload

        except jwt.ExpiredSignatureError:
            logging.debug('Token expired')
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError as e:
            logging.debug('Invalid claims')
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.',
                'InnerException': str(e)
            }, 401)
        except Exception as e:
            logging.debug('Unable to parse authentication token: %s', e)
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    logging.debug('Unable to find the appropriate key')
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)

'''
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
# The 'requires_auth' function is a function decorator that checks if a user has the necessary permissions.
# It takes as an argument a string 'permissions' that represents the necessary permissions.
def requires_auth(permissions=''):
    # The 'requires_auth_decorator' function is the actual decorator that will be applied to the function 'f'.
    def requires_auth_decorator(f):
        # The 'wraps' decorator is used to preserve the signature of the original function 'f'.
        @wraps(f)
        def wrapper(*args, **kwargs):
            # The 'get_token_auth_header' function is called to get the token from the authorization header.
            token = get_token_auth_header()
            try:
                # The token is verified and decoded using the 'verify_decode_jwt' function.
                payload = verify_decode_jwt(token)
            except Exception as e:
                # If an exception occurs during the verification and decoding of the token, 
                # the exception is printed and a 401 error is returned.
                pprint.pprint('Exception: ' + str(e))
                abort(401)

            # The 'check_permissions' function is called to check if the permissions in the payload include the necessary permission.
            check_permissions(permissions, payload)
            
            # If the permission check is successful, the original function 'f' is called with the payload and any other arguments and returns the result.
            return f(payload, *args, **kwargs)
        # The decorator returns the 'wrapper' function.
        return wrapper
    # The 'requires_auth' function returns the 'requires_auth_decorator' decorator.
    return requires_auth_decorator
