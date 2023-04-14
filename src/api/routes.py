"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import bcrypt
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, get_jwt
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
    else :
        access_token = create_access_token(identity=user.serialize())
        return jsonify(message='Login successfully', access_token= access_token), 200
    


    #Se debe buscar copiar el token de login "contraseña" e insertalo en autentication,
    #beare token para poder tener el permiso de obtenerlo 

@api.route('/private/<int:id>', methods=['GET'])
@jwt_required()
def get_all_id(id):
        user = User.query.get(id)
        #el get_jwt otros tipos de funcionalidad , como fresh , expiracion del token , etc 
        token = get_jwt()
        print(token)
        return jsonify(user.serialize()), 200
        
@api.route('/private', methods=['GET'])
def handle_hello():
    all_user = User.query.all()
    # another form to do it 
    # serialize_all_user = [user.serialize() for user in all_user]
    serialize_all_user = list(map(lambda user : user.serialize(), all_user))
    print(all_user)
    return jsonify(serialize_all_user), 200
   