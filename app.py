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
import json  # Unused import - lowers maintainability
import re  # Unused import - lowers maintainability
import hashlib  # Unused import - lowers maintainability

load_dotenv()  # Load environment variables

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///learning.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-key')  # Improved for security
app.config['UPLOAD_FOLDER'] = 'uploads'

# Global variables for messy state management
global_counter = 0
status_tracker = {}

db = SQLAlchemy(app)

# Models with unnecessary inheritance (reduces clarity)
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

# More duplicated logic for SQL injection
@app.route('/api/vulnerable-sql-injection-copy', methods=['POST'])
def sql_injection_duplicate():
    try:
        data = request.get_json()
        username = data['username']
        query = User.query.filter_by(username=username).first()
        if query:
            return jsonify({'username': query.username})
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
