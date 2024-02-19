import os
import pprint
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
'''
# db_drop_and_create_all()

# ROUTES
'''
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''

# Endpoint to get a list of all drinks
@app.route('/drinks', methods=['GET'])
@requires_auth('get:drinks')  # Requires 'get:drinks' permission
def get_drinks(payload):  # The payload from the requires_auth decorator
    try:
        drinks = Drink.query.all()  # Query all drinks
        return jsonify({
            'success': True,
            'drinks': [drink.short() for drink in drinks]  # Return short form of drinks
        }), 200
    except Exception as e:
        pprint.pprint(e)
        abort(500)  # If there's an error, return 500 Internal Server Error

# Endpoint to get detailed information of all drinks
@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')  # Requires 'get:drinks-detail' permission
def get_drinks_detail(payload):  # The payload from the requires_auth decorator
    try:
        drinks = Drink.query.all()  # Query all drinks
        return jsonify({
            'success': True,
            'drinks': [drink.long() for drink in drinks]  # Return long form of drinks
        }), 200
    except Exception:
        abort(500)  # If there's an error, return 500 Internal Server Error

# Endpoint to create a new drink
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')  # Requires 'post:drinks' permission
def create_drink(payload):  # The payload from the requires_auth decorator
    body = request.get_json()  # Get the request body

    if not ('title' in body and 'recipe' in body):  # Check if title and recipe are in the request body
        abort(422)  # If not, return 422 Unprocessable Entity

    title = body.get('title')  # Get the title from the request body
    recipe = body.get('recipe')  # Get the recipe from the request body

    try:
        drink = Drink(title=title, recipe=json.dumps(recipe))  # Create a new Drink object
        drink.insert()  # Insert the new drink into the database

        return jsonify({
            'success': True,
            'drinks': [drink.long()]  # Return the long form of the new drink
        }), 200

    except Exception:
        abort(422)  # If there's an error, return 422 Unprocessable Entity

# Endpoint to update a drink
@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')  # Requires 'patch:drinks' permission
def update_drink(payload, id):  # The payload from the requires_auth decorator and the id of the drink to update
    drink = Drink.query.filter(Drink.id == id).one_or_none()  # Query the drink with the given id

    if drink is None:  # If the drink doesn't exist
        abort(404)  # Return 404 Not Found

    body = request.get_json()  # Get the request body

    try:
        if 'title' in body:  # If title is in the request body
            drink.title = body.get('title')  # Update the title of the drink

        if 'recipe' in body:  # If recipe is in the request body
            drink.recipe = json.dumps(body.get('recipe'))  # Update the recipe of the drink

        drink.update()  # Update the drink in the database

        return jsonify({
            'success': True,
            'drinks': [drink.long()]  # Return the long form of the updated drink
        }), 200

    except Exception:
        abort(400)  # If there's an error, return 400 Bad Request

# Endpoint to delete a drink
@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')  # Requires 'delete:drinks' permission
def delete_drink(payload, id):  # The payload from the requires_auth decorator and the id of the drink to delete
    drink = Drink.query.filter(Drink.id == id).one_or_none()  # Query the drink with the given id

    if drink is None:  # If the drink doesn't exist
        abort(404)  # Return 404 Not Found

    try:
        drink.delete()  # Delete the drink from the database

        return jsonify({
            'success': True,
            'delete': id  # Return the id of the deleted drink
        }), 200

    except Exception:
        abort(500)  # If there's an error, return 500 Internal Server Error


# Error Handling
'''
Example error handling for unprocessable entity
'''

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


# Manipulador de erro para o erro 404
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404

# Manipulador de erro para o erro AuthError
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response
