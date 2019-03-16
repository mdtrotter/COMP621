from app import login, db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
from sqlalchemy.types import DateTime

#get user information from database based on id
@login.user_loader
def load_user(id):
    return User.query.get(int(id))

#Database table for Users
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty = db.Column(db.Boolean)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    student = db.relationship('Student', backref='student')

    def set_username(self, uname):
        self.username = generate_password_hash(uname)

    def check_username(self, uname):
        return check_password_hash(self.username, uname)

    #takes password and creates hash, then saves it 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    #checks password hash against password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    #defines what calling user object will return (in termainal)
    def __repr__(self):
        return '<User {}>'.format(self.username)

#defines student table in database (includes foreign key to User table)
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(64), index=True)
    lastName = db.Column(db.String(64), index=True)
    bannerID = db.Column(db.String(64))
    address = db.Column(db.String(64))
    phone = db.Column(db.String(64))
    gpa = db.Column(db.String(64))
    creditTotal = db.Column(db.String(64))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))

#stores timestamp of last login for each user
class LoginTime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placeholder  = db.Column(db.Integer)
    created = db.Column(db.DateTime, server_default = db.func.now())
    timestamp = db.Column(db.DateTime(timezone=True), server_default = db.func.now(), onupdate = db.func.now())

#stores timestamp of last edit by user
class EditTime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placeholder  = db.Column(db.Integer)
    created = db.Column(db.DateTime, server_default = db.func.now())
    timestamp = db.Column(db.DateTime(timezone=True), server_default = db.func.now(), onupdate = db.func.now())

#stores timestamp of last registration of user (defaults to time of account creation for student)
class RegistrationTime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placeholder  = db.Column(db.Integer)
    created = db.Column(db.DateTime, server_default = db.func.now())
    timestamp = db.Column(db.DateTime(timezone=True), server_default = db.func.now(), onupdate = db.func.now())