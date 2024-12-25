from flask import Flask, request, jsonify, make_response
import jwt
import datetime
from functools import wraps
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Initialize Flask app
app = Flask(__name__)

# Secret keys for JWT and AES
app.config['SECRET_KEY'] = 'your_jwt_secret_key'
AES_KEY = os.urandom(32)  # 256-bit key for AES encryption
AES_IV = os.urandom(16)  # Initialization vector

# Configure logging
logging.basicConfig(
    filename='api_requests.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Mock database to store encrypted data (key-value store for simplicity)
database = {}

# Mock user database
users = {
    "testuser": "password123",
    "admin": "adminpass"
}

# Token-required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            token = request.args.get('token')

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            if "Bearer " in token:
                token = token.split()[1]

            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except Exception as e:
            return jsonify({"message": "Invalid or expired token!"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# AES encryption and decryption functions
def encrypt_data(data):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data.encode()) + encryptor.finalize()

def decrypt_data(encrypted_data):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Save sensitive data to the mock database
def save_to_database(key, plaintext_data):
    encrypted_data = encrypt_data(plaintext_data)
    database[key] = encrypted_data

# Retrieve and decrypt data from the mock database
def retrieve_from_database(key):
    encrypted_data = database.get(key)
    if not encrypted_data:
        return None
    return decrypt_data(encrypted_data).decode()

# Login route
@app.route('/login', methods=['POST'])
def login():
    auth = request.form
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Missing username or password', 400)

    username = auth.get('username')
    password = auth.get('password')

    if username in users and users[username] == password:
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token})

    return make_response('Invalid username or password', 401)

# Protected route to retrieve sensitive data
@app.route('/data', methods=['GET'])
@token_required
def get_data(current_user):
    logging.info(f"User '{current_user}' accessed /data")

    # Retrieve and decrypt the sensitive data from the mock database
    sensitive_data = retrieve_from_database("sensitive_data")

    if not sensitive_data:
        return jsonify({"message": "No sensitive data found!"}), 404

    return jsonify({
        "message": "Access granted!",
        "sensitive_data": sensitive_data
    })

# Route to add sensitive data (for demonstration purposes)
@app.route('/add_data', methods=['POST'])
@token_required
def add_data(current_user):
    logging.info(f"User '{current_user}' accessed /add_data")

    sensitive_data = request.json.get('sensitive_data')

    if not sensitive_data:
        return jsonify({"message": "No data provided!"}), 400

    save_to_database("sensitive_data", sensitive_data)

    return jsonify({"message": "Sensitive data saved successfully!"})

# Index route with login form (HTML)
@app.route('/', methods=['GET'])
def index():
    return '''
    <h1>Login Form</h1>
    <form action="/login" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"><br><br>
        <button type="submit">Login</button>
    </form>
    '''

if __name__ == '__main__':
    # Save mock sensitive data to the database on app start
    save_to_database("sensitive_data", "This is sensitive data!")
    app.run(debug=True)
