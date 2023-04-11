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
    data= request.get_json()
    # new_user= User(data['email'], data['password'],)
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    new_user = User(email =data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize())




@api.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if email != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = register(identity=email)
    return jsonify(access_token=access_token)
    # hashed = bcrypt.hashpw(body['password'], bcrypt.gensalt())
    # print(hashed)
    # response_body = {
    #     "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    # }

    # return jsonify(response_body), 200