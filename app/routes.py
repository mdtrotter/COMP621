from app import app, db
from app.forms import LoginForm, RegistrationForm, EditForm
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Student, LoginTime, EditTime, RegistrationTime
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from flask_recaptcha import ReCaptcha
from functools import wraps
import requests

def check_recaptcha(f):
    """
    Checks Google  reCAPTCHA.

    :param f: view function
    :return: Function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request.recaptcha_is_valid = None

        if request.method == 'POST':
            data = {
                'secret': '6LelApgUAAAAAECZvdK2yjvvQp-2wSDDkAAjPee6',
                'response': request.form.get('g-recaptcha-response'),
                'remoteip': request.access_route[0]
            }
            r = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data=data
            )
            result = r.json()

            if result['success']:
                request.recaptcha_is_valid = True
            else:
                request.recaptcha_is_valid = False
                flash('Invalid reCAPTCHA. Please try again.', 'error')

        return f(*args, **kwargs)

    return decorated_function

#Defines routing when calling url '/' or '/index'
@app.route('/')
@app.route('/index')
def index():
    #check if user is logged in, else send to login page
    if current_user.is_authenticated:
        return render_template('index.html', title='Home Page', user=User.query.all(), student=Student.query.all(), loginTime = LoginTime.query.filter_by(id = current_user.id).first(), editTime = EditTime.query.filter_by(id = current_user.id).first(), registrationTime = RegistrationTime.query.filter_by(id = current_user.id).first())
    else:
        return redirect(url_for('login'))

#Defines routing when calling '/index' and passing an argument through GET
@app.route('/index/<id>')
def index2(id):
    if current_user.is_authenticated:
        return render_template('index.html', title='Home Page', student=Student.query.filter_by(id=current_user.id).first(), user=User.query.filter_by(id=current_user.id).first(), loginTime = LoginTime.query.filter_by(id = current_user.id).first(), editTime = EditTime.query.filter_by(id = current_user.id).first(), registrationTime = RegistrationTime.query.filter_by(id = current_user.id).first())
    else:
        return redirect(url_for('login'))

#Defines routing for '/login'
#Present login form, or if already login sends user to index page
#Handles unsuccessful login attempt and checks if logged in user is faculy or student
@app.route('/login', methods=['GET', 'POST'])
@check_recaptcha
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit() and request.recaptcha_is_valid:
        user = User.query.all()
        for users in user:
            if users is None or not users.check_username(form.username.data) or not users.check_password(form.password.data):
                flash('Invalid username or password')
                return redirect(url_for('login'))
            login_user(users)

            #create new timestamp for user
            clock = LoginTime.query.filter_by(id = current_user.id).first()
            clock.placeholder += 1
            db.session.add(clock)
            db.session.commit()

            if users.faculty:
                return redirect(url_for('index'))
            else:
                return redirect(url_for('index', id=user.id))
    return render_template('login.html', title='Sign In', form=form)

#Defines routing for logging user out
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

#Defines routing for registration
#shows registration form and creates and places new user in the database
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        form = RegistrationForm()
        if form.validate_on_submit():
            user = User(username=form.username.data, email=form.email.data, faculty=form.faculty.data)
            user.set_password(form.password.data)

            #creates new rows in all tables related to newly created user
            db.session.add(user)
            db.session.add(Student())
            db.session.add(LoginTime(placeholder = 1))
            db.session.add(EditTime(placeholder = 1))
            db.session.add(RegistrationTime(placeholder = 1))
            clock = RegistrationTime.query.filter_by(id = current_user.id).first()
            clock.placeholder += 1
            db.session.add(clock)
            db.session.commit()

            return redirect(url_for('index'))
        return render_template('register.html', title='Register', form=form)
    else:
        return redirect(url_for('login'))

#Defines routing for edit page
#Shows form for student in database by querying Student table with id
#Handles two different cases depending if student table has information with designated id or not
@app.route('/edit/<id>', methods=['GET', 'POST'])
def edit(id):
    if current_user.is_authenticated:
        student = Student.query.filter_by(student_id=id).first()

        clock = EditTime.query.filter_by(id = current_user.id).first()
        clock.placeholder += 1
        db.session.add(clock)
        db.session.commit()

        if student != None:
            form = EditForm(obj=student)
            if form.validate_on_submit():
                form.populate_obj(student)
                db.session.commit()
                return redirect(url_for('index'))
        else:
            form = EditForm()
            if form.validate_on_submit():
                student = Student( firstName=form.firstName.data, lastName=form.lastName.data, bannerID=form.bannerID.data, address=form.address.data, phone=form.phone.data, gpa=form.gpa.data, creditTotal=form.creditTotal.data, student_id=id )
                db.session.add(student)
                db.session.commit()
                if(current_user.faculty == True):
                    return redirect(url_for('index'))
                else:
                    return redirect(url_for('index', id = current_user.id))
        return render_template('edit.html', title='Edit', form=form)
    else:
        return redirect(url_for('login'))