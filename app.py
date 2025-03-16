import os
import random
import string
import subprocess  # Vulnerability: Command injection risk
import pickle  # Vulnerability: Deserialization attack risk
import jwt
from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from dotenv import load_dotenv  # Added for environment variables
import json
import re
import hashlib
import base64  # Added for encoding vulnerability
import requests  # Added for insecure API call vulnerability

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///learning.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'

# Global variables for messy state management
global_counter = 0
status_tracker = {}

# Weak cryptographic practices
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()  # Vulnerability: MD5 is insecure

db = SQLAlchemy(app)

# Models with unnecessary inheritance
class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(BaseModel):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Course(BaseModel):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Exposed API keys via URL - Vulnerability
@app.route('/api/open-api', methods=['GET'])
def insecure_api_call():
    response = requests.get(f"http://example.com/data?api_key={os.getenv('API_KEY')}")  # Vulnerability
    return jsonify(response.json())

# Overcomplicated logic for token generation
def overly_complex_token_logic(length=10):
    complex_value = ''.join(random.choices(string.ascii_letters, k=length))
    if random.choice([True, False]):
        complex_value = complex_value[::-1]  # Reverse conditionally
    return complex_value

@app.route('/predictable-token-complicated', methods=['GET'])
def complex_token():
    token = overly_complex_token_logic(15)
    return jsonify({'token': token})

# Additional command injection vulnerability
@app.route('/api/more-command-injection', methods=['POST'])
def more_command_injection():
    data = request.get_json()
    command = data.get('command')
    try:
        output = subprocess.check_output(command, shell=True).decode('utf-8')  # Command injection vulnerability
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': f'Error executing command: {str(e)}'})

# Extended complex error handling logic
@app.route('/api/error-handling-chaos', methods=['POST'])
def chaotic_error_handling():
    try:
        data = request.get_json()
        if 'command' in data:
            output = subprocess.check_output(data['command'], shell=True).decode('utf-8')
        elif 'filename' in data:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], data['filename'])
            if os.path.exists(file_path):
                return jsonify({'status': 'File exists'})
            else:
                raise FileNotFoundError('File does not exist')
        else:
            raise ValueError('Invalid input')
    except FileNotFoundError as e:
        return jsonify({'error': f'File not found: {str(e)}'})
    except Exception as e:
        return jsonify({'error': f'General Error: {str(e)}'})

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
