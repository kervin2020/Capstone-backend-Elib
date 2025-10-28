import os
from werkzeug.security import generate_password_hash
from flask.cli import with_appcontext
import click
from flask import Flask, request
from flasgger import Swagger
from swagger_config import swagger_template, swagger_config
from dotenv import load_dotenv

# Import des extensions Flask
from config import db, jwt, migrate, cors, bcrypt

# Import des modèles
from models import User, Ebook, Category, Loan

# Importation des blueprints
from routes.route_user import user_bp
from routes.routes_ebook import ebook_bp
from routes.route_category import category_bp
from routes.route_loan import loan_bp
from api_docs import api_bp

# Import des utilitaires
from utils.check_expired_loans import check_and_notify
from utils.email_service import send_email

# Charger les variables d'environnement
load_dotenv()


# =====================================================
# Configuration de l'application Flask
# =====================================================
def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialisation des extensions
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)

    # Configuration CORS
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:5173", "http://127.0.0.1:5173", "https://capstone-backend-elib.onrender.com/api/categories"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })

    # Ajout des headers CORS après chaque requête
    @app.after_request
    def after_request(response):
        origin = request.headers.get('Origin')
        if origin in ['http://localhost:5173', 'http://127.0.0.1:5173']:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH'
        return response

    # Swagger (documentation API)
    Swagger(app, config=swagger_config, template=swagger_template)

    # Route de test (affiche toutes les routes disponibles)
    @app.route('/')
    def index():
        import urllib
        output = []
        for rule in app.url_map.iter_rules():
            methods = ','.join(sorted(rule.methods))
            line = urllib.parse.unquote(f"{methods:25s}  {rule}")
            output.append(line)
        return "<pre>" + '\n'.join(sorted(output)) + "</pre>"

    # Enregistrement des blueprints
    app.register_blueprint(user_bp, url_prefix='/api')
    app.register_blueprint(ebook_bp, url_prefix='/api')
    app.register_blueprint(category_bp, url_prefix='/api')
    app.register_blueprint(loan_bp, url_prefix='/api')
    app.register_blueprint(api_bp)

    # Création des tables si elles n'existent pas
    with app.app_context():
        db.create_all()

    # Enregistrement des commandes CLI
    register_commands(app)

    return app


# =====================================================
# Commande personnalisée : flask create-admin
# =====================================================
@click.command('create-admin')
@with_appcontext
@click.argument('email')
@click.argument('password')
def create_admin(email, password):
    """Créer un utilisateur administrateur."""
    if User.query.filter_by(email=email).first():
        click.echo(f"L'utilisateur {email} existe déjà.")
        return

    hashed_password = generate_password_hash(password)
    admin = User(email=email, password=hashed_password, is_admin=True)
    db.session.add(admin)
    db.session.commit()
    click.echo(f"Administrateur créé avec succès : {email}")


def register_commands(app):
    """Enregistre les commandes CLI personnalisées."""
    app.cli.add_command(create_admin)


# =====================================================
# Instance globale pour Gunicorn (Render, etc.)
# =====================================================
app = create_app()  # ✅ Permet à Render de lancer gunicorn app:app


# =====================================================
# Lancement local
# =====================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
