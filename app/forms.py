from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User, Student

#Creates Login form and sets required fields
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

#Creates Registration form to create 
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    faculty = RadioField('Faculty', coerce = lambda x: x == 'True', choices=[(True, 'Yes'), (False, 'No')])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    #checks database for duplicate usernames
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    #checks databse for duplicate emails
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

#Form template for editing student information
class EditForm(FlaskForm):
    firstName = StringField('First Name')
    lastName = StringField('Last Name')
    bannerID = StringField('Banner ID')
    address = StringField('Address')
    phone = StringField('Phone #')
    gpa = StringField('GPA')
    creditTotal = StringField('Credit Total')
    submit = SubmitField('Edit')