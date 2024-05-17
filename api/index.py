import csv
from datetime import datetime, timedelta
import os
from flask import Flask, render_template, send_file, request, jsonify, send_from_directory, Blueprint, session
from flask_cors import CORS
import pandas as pd
from sqlalchemy.orm import joinedload, relationship
from sqlalchemy import func, and_, desc
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import io
import openpyxl
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
bcrypt = Bcrypt(app)

CORS(app)

# Define environment variables
DATABASE_URL = "sqlite:///smartbin.db"
SECRET_KEY = 'Maha0508@#$'

# Set the upload folder and allowed extensions for uploaded files
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx'}

# Define the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

# Initialize the SQLAlchemy db object with the Flask app
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(60))
    user_type = db.Column(db.String(60))
    updated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime)
    last_active = db.Column(db.DateTime)
    status = db.Column(db.String(30))
    fname = db.Column(db.String(30))
    lname = db.Column(db.String(30))
    
class BinConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    binid = db.Column(db.BigInteger, unique=True, nullable=False)
    partnumber = db.Column(db.BigInteger, nullable=False)
    partdescription = db.Column(db.String(300), nullable=False)
    partweight = db.Column(db.BigInteger, nullable=False)
    binweight = db.Column(db.BigInteger, nullable=False)
    bincapacity = db.Column(db.BigInteger, nullable=False)
    minthresh = db.Column(db.Float, nullable=False)
    midthresh = db.Column(db.Float, nullable=False)
    

class BinLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    binid = db.Column(db.BigInteger, nullable=False)
    quantityavailable = db.Column(db.BigInteger, nullable=False)
    batteryindicator = db.Column(db.String(300), nullable=False)
    lastupdatetime = db.Column(db.DateTime, nullable=False)

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"message": "Bad Request", "type": "400"}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"message": "Unauthorized", "type": "401"}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"message": "Forbidden", "type": "403"}), 403

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"message": "Not Found", "type": "404"}), 404

@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({"message": "Too Many Requests", "type": "429"}), 429

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({"message": "Internal Server Error", "type": "500"}), 500

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Check if logged in
def is_logged_in():
    return 'user_id' in session

# Generate a user token
def generate_user_token():
    return secrets.token_urlsafe(32)

# Decorator to protect routes with session checks
def requires_login(f):
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"message": "log in please !!"}, 401)
        return f(*args, **kwargs)
    return decorated_function

# Automatic logout mechanism
@app.before_request
def before_request():
    api_key = request.headers.get('X-API-Key')
    if api_key != app.config['SECRET_KEY']:
        return jsonify({"message": "no-api-key"}, 401)
    
    if is_logged_in():
        last_active = session.get('last_active', datetime.now())
        if datetime.now() - last_active > timedelta(minutes=15):
            # User has been inactive for more than 15 minutes, log them out
            session.pop('user_id', None)
            session.pop('user_token', None)
        session['last_active'] = datetime.now()

@app.route('/', endpoint='index')
def index():
    return jsonify({"message": "Welcome to SmartBin API"})

@app.route('/login', methods=['POST'], endpoint='login')
def login_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Check if either username or email is provided and prioritize email if both are provided
    if email:
        user = User.query.filter_by(email=email).first()
    elif username:
        user = User.query.filter_by(username=username).first()
    else:
        return jsonify({"message": "Invalid input"})

    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['user_type'] = user.user_type
        print("logged in")
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"message": "Invalid credentials"})

@app.route('/logout', endpoint='logout')
def logout_user():
    session.pop('user_id', None)
    session.pop('user_token', None)
    return jsonify({"message": "Logged out successfully"})

@app.route('/session_status', methods=['GET'], endpoint='session_status')
def get_session_status():
    if 'user_id' in session:
        user_id = session['user_id']
        user_type = session['user_type']
        return jsonify({"message": "User is logged in with ID " + str(user_id) + " and user type " + user_type})
    else:
        return jsonify({"message": "User is not logged in"})

@app.route('/data/bin', methods=['POST'])
def handle_data():
    try:
        # Get the data from the POST request 
        quantityavailable1 = float(request.form.get('sendval3'))     
        quantityavailable = abs(quantityavailable1)
        batteryindicator = 1
        binid = request.form.get('binid')

        # Store the data in the database
        binlog = BinLog(binid=binid, quantityavailable=quantityavailable, batteryindicator=batteryindicator, lastupdatetime=datetime.now())
        db.session.add(binlog)
        db.session.commit()

        print(f"Received data from bin: {binid}, {quantityavailable}, {batteryindicator}")
        return jsonify({"message": "Data received and saved successfully"}), 200        

    except Exception as e:
        print(f"Error processing data: {e}")
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500

@app.route('/users', methods=['GET'], endpoint='users')
def list_users():
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(user_list)

@app.route('/user/<int:id>', methods=['GET'], endpoint='userbyid')
def get_user(id):
    user = User.query.get(id)
    if user:
        return jsonify({"id": user.id, "username": user.username, "email": user.email, "fname": user.fname, "lname": user.lname, "user_type": user.user_type, "status": user.status})
    else:
        return jsonify({"message": "User not found"})

@app.route('/user/add', methods=['POST'], endpoint='useradd')
def add_user():
    data = request.get_json()
    fname = data.get("fname")
    lname = data.get("lname")
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')     
    user_type = data.get('user_type')
    status = 1
    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User(fname=fname, lname=lname, username=username, email=email, password=hashed_password, user_type=user_type, status=status)

    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User added successfully"})

@app.route('/user/<int:id>', methods=['DELETE'], endpoint='userdelete')
def delete_user(id):
    user = User.query.get(id)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    else:
        return jsonify({"message": "User not found"})

@app.route('/user/<int:id>', methods=['PUT'], endpoint='userupdate')
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "User not found"})

    data = request.get_json()
    user.fname = data.get("fname")
    user.lname = data.get("lname")
    user.username = data.get('username')
    user.email = data.get('email')
    user.password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8') if data.get('password') else user.password
    user.user_type = data.get('user_type')
    user.status = data.get('status')
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

@app.route('/binc', methods=['POST'])
def add_binc():
    try:
        data = request.get_json()
        partnumber = data.get('partnumber')
        partdescription = data.get('partdescription')
        partweight = data.get('partweight')
        binweight = data.get('binweight')
        bincapacity = data.get('bincapacity')
        minthresh = data.get('minthresh')
        midthresh = data.get('midthresh')

        binc = BinConfig(partnumber=partnumber, partdescription=partdescription, partweight=partweight, binweight=binweight, bincapacity=bincapacity, minthresh=minthresh, midthresh=midthresh)

        db.session.add(binc)
        db.session.commit()
        return jsonify({"message": "Bin configuration added successfully"})
    except Exception as e:
        return jsonify({"message": "Error adding bin configuration", "error": str(e)}), 500

@app.route('/binc/<int:id>', methods=['PUT'])
def update_binc(id):
    try:
        binc = BinConfig.query.get(id)
        if not binc:
            return jsonify({"message": "Bin configuration not found"}), 404

        data = request.get_json()
        binc.partnumber = data.get('partnumber', binc.partnumber)
        binc.partdescription = data.get('partdescription', binc.partdescription)
        binc.partweight = data.get('partweight', binc.partweight)
        binc.binweight = data.get('binweight', binc.binweight)
        binc.bincapacity = data.get('bincapacity', binc.bincapacity)
        binc.minthresh = data.get('minthresh', binc.minthresh)
        binc.midthresh = data.get('midthresh', binc.midthresh)

        db.session.commit()
        return jsonify({"message": "Bin configuration updated successfully"})
    except Exception as e:
        return jsonify({"message": "Error updating bin configuration", "error": str(e)}), 500

@app.route('/binc/<int:id>', methods=['DELETE'])
def delete_binc(id):
    try:
        binc = BinConfig.query.get(id)
        if not binc:
            return jsonify({"message": "Bin configuration not found"}), 404

        db.session.delete(binc)
        db.session.commit()
        return jsonify({"message": "Bin configuration deleted successfully"})
    except Exception as e:
        return jsonify({"message": "Error deleting bin configuration", "error": str(e)}), 500

@app.route('/binlog/<int:binid>', methods=['GET'])
def get_binlog(binid):
    binlog = BinLog.query.filter_by(binid=binid).first()
    if binlog:
        return jsonify({"binid": binlog.binid, "quantityavailable": binlog.quantityavailable, "batteryindicator": binlog.batteryindicator, "lastupdatetime": binlog.lastupdatetime})
    else:
        return jsonify({"message": "Bin log not found"})

@app.route('/binlogs', methods=['GET'])
def get_binlogs():
    binlogs = BinLog.query.all()
    binlog_list = [{"id": binlog.id, "binid": binlog.binid, "quantityavailable": binlog.quantityavailable, "batteryindicator": binlog.batteryindicator, "lastupdatetime": binlog.lastupdatetime} for binlog in binlogs]
    return jsonify(binlog_list)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"})
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"message": "File uploaded successfully"})
    else:
        return jsonify({"message": "File type not allowed"})

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        return jsonify({"message": "File not found", "error": str(e)}), 404

@app.route('/file', methods=['POST'])
def handle_file():
    try:
        if 'file' not in request.files:
            return jsonify({"message": "No file part"})
        file = request.files['file']
        if file.filename == '':
            return jsonify({"message": "No selected file"})
        if not allowed_file(file.filename):
            return jsonify({"message": "File type not allowed"})
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        data = pd.read_excel(file_path, engine='openpyxl')
        excel_data = data.to_dict(orient='records')

        for row in excel_data:
            new_bin_config = BinConfig(
                binid=row['binid'],
                partnumber=row['partnumber'],
                partdescription=row['partdescription'],
                partweight=row['partweight'],
                binweight=row['binweight'],
                bincapacity=row['bincapacity'],
                minthresh=row['minthresh'],
                midthresh=row['midthresh']
            )
            db.session.add(new_bin_config)

        db.session.commit()
        return jsonify({"message": "File uploaded and data saved to the database successfully"})

    except Exception as e:
        return jsonify({"message": "Error processing file", "error": str(e)}), 500

@app.route('/binconfig', methods=['GET'])
def get_binconfig():
    binconfigs = BinConfig.query.all()
    binconfig_list = [{"id": binconfig.id, "binid": binconfig.binid, "partnumber": binconfig.partnumber, "partdescription": binconfig.partdescription, "partweight": binconfig.partweight, "binweight": binconfig.binweight, "bincapacity": binconfig.bincapacity, "minthresh": binconfig.minthresh, "midthresh": binconfig.midthresh} for binconfig in binconfigs]
    return jsonify(binconfig_list)

@app.route('/binconfig/<int:id>', methods=['GET'])
def get_binconfig_by_id(id):
    binconfig = BinConfig.query.get(id)
    if binconfig:
        return jsonify({"id": binconfig.id, "binid": binconfig.binid, "partnumber": binconfig.partnumber, "partdescription": binconfig.partdescription, "partweight": binconfig.partweight, "binweight": binconfig.binweight, "bincapacity": binconfig.bincapacity, "minthresh": binconfig.minthresh, "midthresh": binconfig.midthresh})
    else:
        return jsonify({"message": "Bin configuration not found"})

@app.route('/binconfig/add', methods=['POST'])
def add_binconfig():
    try:
        data = request.get_json()
        binconfig = BinConfig(
            binid=data['binid'],
            partnumber=data['partnumber'],
            partdescription=data['partdescription'],
            partweight=data['partweight'],
            binweight=data['binweight'],
            bincapacity=data['bincapacity'],
            minthresh=data['minthresh'],
            midthresh=data['midthresh']
        )
        db.session.add(binconfig)
        db.session.commit()
        return jsonify({"message": "Bin configuration added successfully"})
    except Exception as e:
        return jsonify({"message": "Error adding bin configuration", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
    db.create_all()

