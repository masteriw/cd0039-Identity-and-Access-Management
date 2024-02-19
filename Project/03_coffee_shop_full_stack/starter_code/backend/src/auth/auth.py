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
Esta função é usada para obter o token de acesso do cabeçalho de 
autorização da solicitação HTTP. Ela verifica se o cabeçalho de 
autorização está presente e se o esquema de autorização é “Bearer”. 
Em seguida, ela retorna o token de acesso.
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
# A função check_permissions verifica se uma permissão específica está presente no payload.
def check_permissions(permission, payload):
    # Verifica se a chave 'permissions' está presente no payload.
    # Se não estiver, uma exceção AuthError é lançada com uma mensagem de erro específica.
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    # Verifica se a permissão específica está presente na lista de permissões do payload.
    # Se não estiver, uma exceção AuthError é lançada com uma mensagem de erro específica.
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
Esta função é usada para verificar e decodificar o JWT. 
Ela obtém as chaves públicas do seu domínio Auth0, verifica se o JWT 
tem um “kid” no cabeçalho, e então usa a chave apropriada para 
decodificar o JWT. Ela também verifica se o JWT não expirou e se as 
reivindicações (claims) são corretas.
'''
def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        logging.debug('Key ID not in unverified header')
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

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
# A função 'requires_auth' é um decorador de função que verifica se um usuário tem as permissões necessárias.
# Ela recebe como argumento uma string 'permissions' que representa as permissões necessárias.
def requires_auth(permissions=''):
    # A função 'requires_auth_decorator' é o decorador real que será aplicado à função 'f'.
    def requires_auth_decorator(f):
        # O decorador 'wraps' é usado para preservar a assinatura da função original 'f'.
        @wraps(f)
        def wrapper(*args, **kwargs):
            # A função 'get_token_auth_header' é chamada para obter o token do cabeçalho de autorização.
            token = get_token_auth_header()
            try:
                # O token é verificado e decodificado usando a função 'verify_decode_jwt'.
                payload = verify_decode_jwt(token)
            except Exception as e:
                # Se ocorrer uma exceção durante a verificação e decodificação do token, 
                # a exceção é impressa e um erro 401 é retornado.
                pprint.pprint('Exception: ' + str(e))
                abort(401)

            # A função 'check_permissions' é chamada para verificar se as permissões no payload incluem a permissão necessária.
            check_permissions(permissions, payload)
            
            # Se a verificação de permissões for bem-sucedida, a função original 'f' é chamada com o payload e quaisquer outros argumentos e retorna o resultado.
            return f(payload, *args, **kwargs)
        # O decorador retorna a função 'wrapper'.
        return wrapper
    # A função 'requires_auth' retorna o decorador 'requires_auth_decoraor'.
    return requires_auth_decorator
