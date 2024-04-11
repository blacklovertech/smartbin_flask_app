from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

db = SQLAlchemy()

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


