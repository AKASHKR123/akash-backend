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

# Deeply nested and redundant logic
def complex_validation(data):
    if isinstance(data, dict):
        if 'username' in data:
            if isinstance(data['username'], str):
                if len(data['username']) > 5:
                    if data['username'].isalnum():
                        if 'password' in data:
                            if isinstance(data['password'], str):
                                if len(data['password']) > 8:
                                    return True
    return False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Duplicated logic (reduces maintainability)
@app.route('/predictable-token', methods=['GET'])
def predictable_token1():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    return jsonify({'token': token})

@app.route('/predictable-token-copy', methods=['GET'])
def predictable_token2():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    return jsonify({'token': token})

# Repetitive error handling
@app.route('/api/vulnerable-sql-injection', methods=['POST'])
def improved_sql():
    try:
        data = request.get_json()
        username = data['username']
        query = User.query.filter_by(username=username).first()
        if query:
            return jsonify({'username': query.username})
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        try:
            return jsonify({'error': str(e)}), 500
        except:
            return jsonify({'error': 'Unknown error'}), 500

# Repeated code for command injection
@app.route('/api/command-injection', methods=['POST'])
def command_injection1():
    data = request.get_json()
    command = data.get('command')
    try:
        output = subprocess.check_output(command, shell=True).decode('utf-8')
    except Exception as e:
        output = f'Error executing command: {str(e)}'
    return jsonify({'output': output})

@app.route('/api/command-injection-duplicate', methods=['POST'])
def command_injection2():
    data = request.get_json()
    command = data.get('command')
    try:
        output = subprocess.check_output(command, shell=True).decode('utf-8')
    except Exception as e:
        output = f'Error executing command: {str(e)}'
    return jsonify({'output': output})

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
