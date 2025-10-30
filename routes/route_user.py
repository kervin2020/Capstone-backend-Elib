from flask import Blueprint, request, jsonify
from models import User
from config import db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

# Blueprint for user routes
user_bp = Blueprint('user_bp', __name__)


# Check if user is admin
def _require_admin(user_id=None):
    """
    Vérifie si l'utilisateur est administrateur.

    securite:
    - Si user_id est None, vérifie si l'utilisateur actuel est admin.
      jwt: [ ]
      response: 403 
       description: Accès interdit, vous n'êtes pas administrateur
      response: 200
        description: Accès autorisé
    """
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"msg": "Utilisateur non trouvé"}), 404
    if user_id is None:
        if not user.is_admin:
            return jsonify({"msg": "Accès interdit, vous n'êtes pas administrateur"}), 403
    else:
        if not (user.is_admin or get_jwt_identity() == user_id):
            return jsonify({"msg": "Accès interdit, vous n'êtes pas propriétaire du compte ou administrateur"}), 403
    return None


# Create user
@user_bp.route('/users', methods=['POST'])
def create_user():
    """ 
    Créer un nouvel utilisateur (inscription)
    ---
    tags:
      - Utilisateurs
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
            email:
              type: string
            password:
              type: string
            is_admin:
              type: boolean
              default: false
    responses:
      201:
        description: Utilisateur créé avec succès.
      400:
        description: Données manquantes ou email déjà utilisé.
    """
    data = request.get_json()

    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"msg": "Nom d'utilisateur, email et mot de passe sont requis"}), 400

    new_user = User(
        username=data['username'],
        email=data['email'],
        password=User.hash_password(data['password']),
        is_admin=data.get('is_admin', False)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "msg": "Utilisateur créé avec succès",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "is_admin": new_user.is_admin
        }
    }), 201


# Get all users
@user_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    """ 
    Lister tous les utilisateurs (Admin requis)
    ---
    tags:
      - Utilisateurs
    security:
      - Bearer: []
    responses:
      200:
        description: Une liste de tous les utilisateurs.
      403:
        description: Accès non autorisé (admin requis).
    """
    err = _require_admin()
    if err:
        return err

    users = User.query.all()
    return jsonify({'users': [
        {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'created_at': user.created_at
        } for user in users
    ]}), 200


# Get specific user
@user_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """ 
    Obtenir les détails d'un utilisateur spécifique
    Accessible par l'utilisateur concerné ou un admin.
    ---
    tags:
      - Utilisateurs
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Détails de l'utilisateur.
      403:
        description: Accès non autorisé.
      404:
        description: Utilisateur non trouvé.
    """
    err = _require_admin(user_id)
    if err:
        return err

    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'created_at': user.created_at
    }), 200


# Update user
@user_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """
    Mettre à jour un utilisateur
    Accessible par l'utilisateur concerné ou un admin.
    ---
    tags:
      - Utilisateurs
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            username:
              type: string
            email:
              type: string
    responses:
      200:
        description: Utilisateur mis à jour avec succès.
      403:
        description: Accès non autorisé.
    """
    err = _require_admin(user_id)
    if err:
        return err

    user = User.query.get_or_404(user_id)
    data = request.get_json()

    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    if 'password' in data:
        user.password = User.hash_password(data['password'])
    user.is_admin = data.get('is_admin', user.is_admin)

    db.session.commit()

    return jsonify({
        "msg": "Utilisateur mis à jour avec succès",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        }
    }), 200


# Delete user
@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """
    Supprimer un utilisateur
    Accessible par l'utilisateur concerné ou un admin.
    ---
    tags:
      - Utilisateurs
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Utilisateur supprimé avec succès.
      403:
        description: Accès non autorisé.
    """
    err = _require_admin(user_id)
    if err:
        return err

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()

    return jsonify({"msg": "Utilisateur supprimé avec succès"}), 200


# Get current user
@user_bp.route('/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """
    Obtenir les détails de l'utilisateur actuellement connecté
    ---
    tags:
      - Utilisateurs
    security:
      - Bearer: []
    responses:
      200:
        description: Détails de l'utilisateur connecté.
      404:
        description: Utilisateur non trouvé.
    """
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'created_at': user.created_at
    }), 200


# User login
@user_bp.route('/login', methods=['POST'])
def login():
    """
    Connexion d'un utilisateur pour obtenir un token JWT
    ---
    tags:
      - Authentification
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Connexion réussie, retourne un access_token.
      400:
        description: Email ou mot de passe manquant.
      401:
        description: Identifiants invalides.
    """
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({"msg": "Email et mot de passe sont requis"}), 400

    user = User.query.filter_by(email=data['email']).first()

    if user and User.check_password(data['password'], user.password):
        access_token = create_access_token(
            identity=user.id, expires_delta=timedelta(hours=1))
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({"msg": "Email ou mot de passe incorrect"}), 401
