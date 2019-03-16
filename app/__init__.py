from flask import Flask, flash
from flask_recaptcha import ReCaptcha
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import requests
from functools import wraps

#creates objects at the initialization of running the app
app = Flask(__name__)
recaptcha = ReCaptcha(app=app)

app.config.update({'RECAPTCHA_ENABLED': True,
                   'RECAPTCHA_SITE_KEY':
                       'site_key',
                   'RECAPTCHA_SECRET_KEY':
                       'secret_key'})

app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

#Import must be here to properly call app object (created in first line above)
from app import routes, models