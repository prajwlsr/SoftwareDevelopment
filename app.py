from flask import Flask,render_template, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from cryptography.fernet import Fernet
import numpy as np
import joblib
import os
import json

app = Flask(__name__, static_folder="", template_folder="")

app.config["JWT_SECRET_KEY"] = "supersecretkey"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
USER_DB_FILE = 'users.json'

encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)


users = {"user1": bcrypt.generate_password_hash("password").decode('utf-8')}

def load_users():
    """Load user data from a JSON file."""
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_users(users):
    """Save user data to a JSON file."""
    with open(USER_DB_FILE, 'w') as file:
        json.dump(users, file)
try:
    anomaly_detector = joblib.load("models/anomaly_detector.pkl")
except FileNotFoundError:
    anomaly_detector = None

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/signin", methods=["POST"])
def signin():
    data = request.json
    username, password, email = data["username"], data["password"], data["email"]
    
    # Load existing users
    users = load_users()

   
    if username in users:
        return jsonify({"message": "User already exists"}), 400
    try:
        users[username] = bcrypt.generate_password_hash(password).decode('utf-8')
        
         
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[username] = hashed_password

       
        save_users(users)
        token = create_access_token(identity=username)
        
        return jsonify({"message": "User registered successfully", "token": token}), 201
    except:
        return jsonify({"message": "User notregistered"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
     

    users = load_users()

    try:
        if username in users and bcrypt.check_password_hash(users[username], password):
            token = create_access_token(identity=username)
      
        return jsonify({"token": token}), 200
    except:
        return jsonify({"message": "Invalid credentials"}), 200

@app.route("/encrypt", methods=["POST"])
@jwt_required()
def encrypt():
    data = request.json["message"]
    encrypted_message = cipher.encrypt(data.encode()).decode()
    return jsonify({"encrypted_message": encrypted_message})

@app.route("/decrypt", methods=["POST"])
@jwt_required()
def decrypt():
    data = request.json["encrypted_message"]
    decrypted_message = cipher.decrypt(data.encode()).decode()
    return jsonify({"decrypted_message": decrypted_message})

if __name__ == "__main__":
    app.run(debug=True)