from app import app, db
from app.forms import LoginForm, RegistrationForm, EditForm
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Student, Time
from werkzeug.urls import url_parse

#Defines routing when calling url '/' or '/index'
@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated:
        clock = Time.query.filter_by(id = 1).first()
        clock.placeholder = 1
        return render_template('index.html', title='Home Page', user=User.query.all(), student=Student.query.all(), time=Time.query.all())
    else:
        return redirect(url_for('login'))

#Defines routing when calling '/index' and passing an argument through GET
@app.route('/index/<id>')
def index2(id):
    if current_user.is_authenticated:
        return render_template('index.html', title='Home Page', student=Student.query.filter_by(student_id=id).first(), user=User.query.filter_by(id=id).first())
    else:
        return redirect(url_for('login'))

#Defines routing for '/login'
#Present login form, or if already login sends user to index page
#Handles unsuccessful login attempt and checks if logged in user is faculy or student
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user)
        if user.faculty:
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
            db.session.add(user)
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
                return redirect(url_for('index'))
        return render_template('edit.html', title='Edit', form=form)
    else:
        return redirect(url_for('login'))