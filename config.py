import os
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt


class Config:
    SECRET_KEY = os.getenv('secret_key', 'supersecret')
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'database_uri', 'sqlite:///bibliotheque.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('jwt_secret_key', 'jwtsecret')
    UPLOAD_FOLDER = 'static/uploads'


db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
cors = CORS()
bcrypt = Bcrypt()
