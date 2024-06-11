from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import secrets

UPLOAD_FOLDER = './Static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(20)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookdb.sqlite3'
db = SQLAlchemy(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.jinja_env.add_extension('jinja2.ext.do')

# load users, roles for a session
login_manager = LoginManager()
login_manager.login_view = '.login'
login_manager.init_app(app)