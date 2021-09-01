from os import abort
from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from passlib.hash import pbkdf2_sha256
import uuid
import pymongo

app = Flask(__name__)

client = pymongo.MongoClient("mongodb://localhost:27017/")

db = client["authDB"]

# Setup the flask jwt extension
app.config['JWT_SECRET_KEY'] = '88712350745A3b289'
jwt = JWTManager(app)

# signup route
@app.route('/register', methods=['POST'])
def register():
    # not json the abort with status 500
    if not request.json:
        abort(500)
        
    # get the values from json
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    name = request.json.get('name', None)
    
    # If any of the field is None abort with status 500
    if username is None or password is None or name is None:
        abort(500)
    
    # check if the username already exists or not
    if db.users.find_one({"username": username}):
        return jsonify("username already exists"), 500
    
    # generating a unique id
    id = uuid.uuid4().hex
    # Hashing the password
    hashed_password = pbkdf2_sha256.hash(password)
    
    # Insert the data in the users collection
    db.users.insert_one({
        "user_id": id,
        "username": username,
        "name": name,
        "password": hashed_password
    })
    
    return jsonify(userid = id)


# login route
@app.route('/login', methods=['POST'])
def login():
    # not json the abort with status 500
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 500

    # getting username and password
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    # If any of the field is None abort with status 500
    if not username:
        return jsonify(msg="Missing username parameter"), 500
    if not password:
        return jsonify(msg="Missing password parameter"), 500
    
    # Find the username in users table
    if db.users.find_one({"username": username}):
        # Getting the password of the user
        pwd = db.users.find_one({"username": username}).get('password')
        
        # If password verification fails then return with status 400
        if not pbkdf2_sha256.verify(password, pwd):
            return jsonify("password failed!"), 400
        
    # generating a access token
    access_token = create_access_token(identity=username)
    # returning the access token
    return jsonify(access_token=access_token), 200 
    
    
if __name__ == "__main__":
    app.run(debug=True)