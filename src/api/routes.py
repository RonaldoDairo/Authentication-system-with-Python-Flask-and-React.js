"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import bcrypt
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
api = Blueprint('api', __name__)



@api.route('/signup', methods=['POST'])
def register():
    body= request.get_json()
    # new_user= User(data['email'], data['password'],)
    #  hacer validacion para de si existe un password  o imail , que diga not fount 404 etc 
    hashed_password = bcrypt.hashpw(body['password'].encode('utf-8'), bcrypt.gensalt(14))
    new_user = User(body['email'], hashed_password.decode())
    db.session.add(new_user)
    db.session.commit()
    print (new_user)
    return jsonify(new_user.serialize()), 201

@api.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    #another form to do it , it used to simple consults 
    # user = User.query.filter_by(email = body['email']).one()

    # This form is complicated 
    #user = db.session.query(User).filter(User.email == body['email']).one()

    # This form is complicated 
    user = db.session.query(User).filter(User.email == body['email']).first()
    if not user:
        return jsonify('There are not user with that gmail'), 400
    if not  bcrypt.checkpw(body['password'].encode('utf-8'), user.password.encode('utf-8')):
        return jsonify('Password Incorrect '), 400
    
    return jsonify('Login successfully'), 200

    # email = request.json.get("email", None)
    # password = request.json.get("password", None)
    # if email != "test" or password != "test":
    #     return jsonify({"msg": "Bad username or password"}), 401

    # access_token = register(identity=email)
    # return jsonify(access_token=access_token)
    # hashed = bcrypt.hashpw(body['password'], bcrypt.gensalt())
    # print(hashed)
    # response_body = {
    #     "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    # }

    # return jsonify(response_body), 200