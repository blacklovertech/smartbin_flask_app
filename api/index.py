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
import mysql.connector
from mysql.connector import Error
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
bcrypt = Bcrypt(app)

CORS(app)
username = 'm5002_smartbin'
password = 'Smartbin@12'
hostname = 'mysql0.serv00.com'
database_name = 'm5002_smartbin_api'

# Define environment variables
DATABASE_URL = f"mysql+pymysql://{username}:{password}@{hostname}/{database_name}"
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

#chck loggeedin
def is_logged_in():
    return 'user_id' in session

# Generate a user token
def generate_user_token():
    return secrets.token_urlsafe(32)

# Decorator to protect routes with session checks
def requires_login(f):
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return jsonify({"message": "log in please !!"},401)
        return f(*args, **kwargs)
    return decorated_function

# Automatic logout mechanism
def before_request():
    
    api_key = request.headers.get('X-API-Key')
    if api_key != app.config['SECRET_KEY']:
        return jsonify({"message": "no-api-key"},401)
    
    if is_logged_in():
        last_active = session.get('last_active', datetime.now())
        if datetime.now() - last_active > timedelta(minutes=15):
            # User has been inactive for more than 15 minutes, log them out
            session.pop('user_id', None)
            session.pop('user_token', None)
        session['last_active'] = datetime.now()


@app.route('/',endpoint='index')
def index():
    
    return jsonify({"message": "Welcome to SmartBin API","dburi":DATABASE_URL})

@app.route('/login', methods=['POST'],endpoint='login')
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
        print("loggedin")
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"message": "Invalid credentials"})

@app.route('/logout',endpoint='logout')
def logout_user():
    session.pop('user_id', None)
    session.pop('user_token', None)
    return jsonify({"message": "Logged out successfully"})

@app.route('/session_status', methods=['GET'],endpoint='session_status')
def get_session_status():
    if 'user_id' in session:
        user_id = session['user_id']
        user_type = session['user_type']
        return jsonify({"message": "User is logged in with ID " + str(user_id) + " and user type " + user_type})
    else:
        return jsonify({"message": "User is not logged in"})

#to get the bin data at the uri
# class BinData(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     sendval = db.Column(db.Float)
#     sendval2 = db.Column(db.Float)
#     sendval3 = db.Column(db.Float)
#     binid = db.Column(db.String(10))

@app.route('/data/bin', methods=['POST'])
def handle_data():
    try:
        # Get the data from the POST request 
                
        quantityavailable1 = float(request.form.get('sendval3'))     
        # quantityavailable2 = round(quantityavailable1,2)
        quantityavailable = abs(quantityavailable1)
        #quantityavailable = request.form.get('sendval2')
        #quantityavailable = abs(request.form.get('sendval'))
        batteryindicator = 1
        binid = request.form.get('binid')

        # Store the data in the database
        binlog = BinLog(binid=binid, quantityavailable=quantityavailable, batteryindicator=batteryindicator, lastupdatetime=datetime.now())
        db.session.add(binlog)
        db.session.commit()

        print(f"Received data from bin: {binid}, {quantityavailable}, {batteryindicator}")
        return jsonify({"message": "Data received and saved successfully"}, 200)        

    except Exception as e:
        print(f"Error processing data: {e}")
        return jsonify({"message": "Internal Server Error", "error": str(e)}, 500)
        

# @app.route('/data/bin/', methods=['POST'])
# def get_data_bin_directly():
#     try:
#             
#         #data = request.form  # Assuming form-encoded data (or adjust based on NodeMCU format)
#         
#         #data = request.get_json()
#         #if data:
#            
#             #bin_id = request.form.get('binid')
#             #quantityavailable = data.get('sendval')
#             #batteryindicator = data.get('sendval2')

#             binlog = BinLog(binid=bin_id, quantityavailable=quantityavailable, batteryindicator=batteryindicator, lastupdatetime=datetime.now())
#             db.session.add(binlog)
#             db.session.commit()
#             return jsonify({"message": "Data received and saved successfully"}, 200)
#         # else:
#         #     return jsonify({"message": "You missed sending data as JSON"}, 400)
#     except Exception as e:
#         return jsonify({"message": "Internal Server Error", "error": str(e)}, 500)

# List Users
@app.route('/users', methods=['GET'],endpoint='users')
#@requires_login
def list_users():
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(user_list)

#get oneuser
@app.route('/user/<int:id>' ,methods=['GET'],endpoint='userbyid')
def get_user(id):
    user = User.query.get(id)
    if user:
        return jsonify({"id": user.id, "username": user.username, "email": user.email,"fname": user.fname,"lname": user.lname,"user_type":user.user_type,"status":user.status})
    else:
        return jsonify({"message": "User not found"})
# Add User
# When registering a user
@app.route('/user/add', methods=['POST'],endpoint='useradd')
def add_user():
    data = request.get_json()
    fname=data.get("fname")
    lname=data.get("lname")
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')     
    user_type = data.get('user_type')
    status = 1
    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User(fname=fname,lname=lname,username=username, email=email, password=hashed_password,user_type=user_type,status=status)

    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User added successfully"})

# Delete User
@app.route('/user/<int:id>', methods=['DELETE'],endpoint='userdelete')
def delete_user(id):
    user = User.query.get(id)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    else:
        return jsonify({"message": "User not found"})

# Update User
@app.route('/user/<int:id>', methods=['PUT'],endpoint='userupdate')
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "User not found"})

    data = request.get_json()
    user.fname=data.get("fname")
    user.lname=data.get("lname")
    user.username = data.get('username')
    user.email = data.get('email')
    user.password = data.get('password')     
    user.user_type = data.get('user_type')
    user.status = 1
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

#list all bins
@app.route('/bins', methods=['GET'],endpoint='bins')
def list_binconfig():
    binconfigs = BinConfig.query.all()
    binconfig_list = [{"id": bin.id, "binid": bin.binid, "partnumber": bin.partnumber, "partdescription": bin.partdescription, "partweight": bin.partweight, "binweight": bin.binweight, "bincapacity": bin.bincapacity, "minthresh": bin.minthresh, "midthresh": bin.midthresh} for bin in binconfigs]
    return jsonify(binconfig_list)

@app.route('/bin/<string:binid>', methods=['GET'],endpoint='binget')
def get_binconfig(binid):
    binconfig = BinConfig.query.filter_by(binid=binid).first()
    if binconfig:
        return jsonify({"id": binconfig.id, "binid": binconfig.binid, "partnumber": binconfig.partnumber, "partdescription": binconfig.partdescription, "partweight": binconfig.partweight, "binweight": binconfig.binweight, "bincapacity": binconfig.bincapacity, "minthresh": binconfig.minthresh, "midthresh": binconfig.midthresh})
    else:
        return jsonify({"message": "Bin not found"})

# Add Bin to BinConfig
@app.route('/bin/add', methods=['POST'],endpoint='binadd')
def add_bin_to_binconfig():
    try:
        data = request.get_json()
	
        # Create a new BinConfig instance based on the JSON data
        bin = BinConfig(
            binid=data.get('binid'),
            partnumber=data.get('partnumber'),
            partdescription=data.get('partdescription'),
            partweight=data.get('partweight'),
            binweight=data.get('binweight'),
            bincapacity=data.get('bincapacity'),
            minthresh=data.get('minthresh'),
            midthresh=data.get('midthresh'),
        )
	
        # Add the BinConfig instance to the database session
        db.session.add(bin)

        # Commit the changes to the database
        db.session.commit()
	
    except Exception as e:
        # Handle exceptions and provide an error response
        db.session.rollback()  # Rollback the transaction in case of an error

# Update BinConfig
@app.route('/bin/update/<int:id>', methods=['PUT'],endpoint='binupdate')
def update_binconfig(id):
    bin = BinConfig.query.get(id)
    if not bin:
        return jsonify({"message": "Bin not found"})

    data = request.get_json()
    for key, value in data.items():
        setattr(bin, key, value)

    db.session.commit()
    return jsonify({"message": "BinConfig updated successfully"})

# Delete Bin from BinConfig
@app.route('/bin/delete/<int:id>', methods=['DELETE'],endpoint='bindelete')
def delete_binconfig(id):
    bin = BinConfig.query.get(id)
    if not bin:
        return jsonify({"message": "Bin not found"})

    db.session.delete(bin)
    db.session.commit()
    return jsonify({"message": "BinConfig deleted successfully"})

@app.route('/binconfigfile/download', methods=['GET'],endpoint='binconfigexcelfiledl')
def download_excel():
    # Specify the path to your pre-existing Excel file
    excel_file_path = 'configuration.xlsx'

    # Serve the Excel file as a response
    return send_file(
        excel_file_path,
        as_attachment=True,
        download_name='binconfig.xlsx',  # Rename the downloaded file if needed
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/upload_xlsx', methods=['POST'],endpoint='uploadexcelfile')
def upload_xlsx():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})
    file = request.files['file']
    if file and file.filename.endswith('.xlsx'):
        insertion_errors = []
        try:
            # Load the XLSX file using openpyxl
            workbook = openpyxl.load_workbook(file, data_only=True)
            worksheet = workbook.active
            # Extract the header row as strings
            header_row = next(worksheet.iter_rows(values_only=True))
            header = [str(cell) for cell in header_row]
            for row in worksheet.iter_rows(values_only=True, min_row=2):  # Start reading from row 2
                data = [str(cell) if cell is not None else None for cell in row]
                if None in data:
                    break  # Stop processing if any column is None
                binid, partnumber, partdescription, partweight, binweight, bincapacity, minthresh, midthresh = data
                bin_config = BinConfig(
                    binid=binid,
                    partnumber=partnumber,
                    partdescription=partdescription,
                    partweight=partweight,
                    binweight=binweight,
                    bincapacity=bincapacity,
                    minthresh=minthresh,
                    midthresh=midthresh
                )
                db.session.add(bin_config)
                db.session.commit()
        except Exception as e:
            insertion_errors.append(f"Error inserting data: {str(e)}")
        if not insertion_errors:
            return jsonify({"message": "Data inserted successfully"})
        else:
            return jsonify({"error": insertion_errors})
    else:
        return jsonify({"error": "Invalid file format. Please upload an XLSX file (.xlsx)"})

# binlogbyid
@app.route('/binlogs', methods=['GET'],endpoint='binlogs')
def list_binlogs():
    subquery = db.session.query(
        BinLog.binid,
        db.func.max(BinLog.lastupdatetime).label('latest_time')
    ).group_by(BinLog.binid).subquery()

    latest_binlogs = db.session.query(BinLog).join(
        subquery, and_(
            BinLog.binid == subquery.c.binid,
            BinLog.lastupdatetime == subquery.c.latest_time
        )
    ).order_by(desc(BinLog.lastupdatetime)).limit(30).all()

    binlog_list = []

    for binlog in latest_binlogs:
        binlog_data = {
            "id": binlog.id,
            "binid": binlog.binid,
            "quantityavailable": binlog.quantityavailable,
            "batteryindicator": binlog.batteryindicator,
            "lastupdatetime": binlog.lastupdatetime,
        }

        bin_config = BinConfig.query.get(binlog.binid)

        if bin_config:
            binlog_data["bin_config"] = {
                "partnumber": bin_config.partnumber,
                "partdescription": bin_config.partdescription,
                "partweight": bin_config.partweight,
                "binweight": bin_config.binweight,
                "bincapacity": bin_config.bincapacity,
                "minthresh": bin_config.minthresh,
                "midthresh": bin_config.midthresh
            }

        quantityavailable = binlog.quantityavailable
        minthresh = bin_config.minthresh if bin_config else 0
        if quantityavailable <= minthresh:
            binstatus = ""
        elif minthresh < quantityavailable < 2 * (bin_config.midthresh if bin_config else 0):
            binstatus = "HALF"
        else:
            binstatus = "FULL"

        binlog_data["binstatus"] = binstatus
        
        binlog_list.append(binlog_data)

    return jsonify(binlog_list)


@app.route('/binlog/<int:binid>', methods=['GET'],endpoint='binlogbyid')
def get_binlogs_by_binid(binid):
    binlogs = BinLog.query.filter_by(binid=binid).order_by(desc(BinLog.lastupdatetime)).all()

    binlog_list = []

    for binlog in binlogs:
        binlog_data = {
            "id": binlog.id,
            "binid": binlog.binid,
            "quantityavailable": binlog.quantityavailable,
            "batteryindicator": binlog.batteryindicator,
            "lastupdatetime": binlog.lastupdatetime,
        }

        bin_config = BinConfig.query.get(binlog.binid)

        if bin_config:
            binlog_data["bin_config"] = {
                "partnumber": bin_config.partnumber,
                "partdescription": bin_config.partdescription,
                "partweight": bin_config.partweight,
                "binweight": bin_config.binweight,
                "bincapacity": bin_config.bincapacity,
                "minthresh": bin_config.minthresh,
                "midthresh": bin_config.midthresh
            }

        quantityavailable = binlog.quantityavailable
        minthresh = bin_config.minthresh if bin_config else 0
        if quantityavailable <= minthresh:
            binstatus = "EMPTY"
        elif minthresh < quantityavailable < 2 * (bin_config.midthresh if bin_config else 0):
            binstatus = "HALF"
        else:
            binstatus = "FULL"

        binlog_data["binstatus"] = binstatus

        binlog_list.append(binlog_data)

    return jsonify(binlog_list)


@app.route('/create_database', methods=['GET'],endpoint='createdb')
def create_database():
    # Create the database and tables
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')
