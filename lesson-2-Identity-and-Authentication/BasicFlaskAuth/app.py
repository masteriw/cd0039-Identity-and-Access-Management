# Importando as bibliotecas necessárias
from flask import Flask, request, abort
import json
from functools import wraps
from jose import jwt
from urllib.request import urlopen

# Inicializando a aplicação Flask
app = Flask(__name__)

'''As constantes AUTH0_DOMAIN, ALGORITHMS e API_AUDIENCE são definidas 
com os valores apropriados para a sua aplicação Auth0.'''
AUTH0_DOMAIN = 'masteriw.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'TestApi'

'''
Esta classe é usada para representar um erro de autenticação. 
Ela herda da classe Exception e tem um código de erro e uma descrição.
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

'''
Esta função é usada para obter o token de acesso do cabeçalho de 
autorização da solicitação HTTP. Ela verifica se o cabeçalho de 
autorização está presente e se o esquema de autorização é “Bearer”. 
Em seguida, ela retorna o token de acesso.
'''
def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token

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
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)

'''Esta é um decorador que é usado para garantir que uma rota específica 
requer autenticação. Ela obtém o token de acesso, verifica e decodifica 
o JWT, e então chama a função original com o payload do JWT como um 
argumento adicional.
'''
def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_auth_header()
        try:
            payload = verify_decode_jwt(token)
        except:
            abort(401)
        return f(payload, *args, **kwargs)

    return wrapper

'''Esta é uma rota que requer autenticação. Ela usa o decorador requires_auth, 
imprime o payload do JWT e retorna “Access Granted”.'''
@app.route('/headers')
@requires_auth
def headers(payload):
    print(payload)
    return 'Access Granted'
