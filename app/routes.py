from app import app, db
from app.forms import LoginForm, RegistrationForm, EditForm
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Student
from werkzeug.urls import url_parse

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home Page', user=User.query.all(), student=Student.query.all())

@app.route('/index/<id>')
def index2(id):
    return render_template('index.html', title='Home Page', student=Student.query.filter_by(student_id=id).first(), user=User.query.filter_by(id=id).first())

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

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, faculty=form.faculty.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)

@app.route('/edit/<id>', methods=['GET', 'POST'])
def edit(id):
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