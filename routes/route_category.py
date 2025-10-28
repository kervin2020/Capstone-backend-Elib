from flask import Blueprint, request, jsonify
from models import Category, User, db
from flask_jwt_extended import jwt_required, get_jwt_identity

category_bp = Blueprint('category_bp', __name__)


# Check if user is admin
def _require_admin():
    """
    verifie si l'utilisateur est administrateur
    securite:
        -jwt:[]
    response:
        200:
            description: Accès autorisé
        403:
            description: Accès interdit, vous n'êtes pas administrateur
    """
    user = User.query.get(get_jwt_identity())
    if not user or not user.is_admin:
        return jsonify({"msg": "Accès interdit, vous n'êtes pas administrateur"}), 403
    return None


# Create new category
@category_bp.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    """
    creer une nouvelle catégorie
    
      tags:
        - categories
        security:
          - jwt: []
        parameters:
          - in: body
            name: category
            schema:
                type: object
                properties:
                    name:
                    type: string
                    description:
                    type: string
                required:
                    - name
        responses:
            201:
                description: Catégorie créée
            400:
                description: Le nom de la catégorie est requis
            403:
                description: Accès interdit, vous n'êtes pas administrateur
    """
    err = _require_admin()
    if err:
        return err

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({"msg": "Le nom de la catégorie est requis"}), 400

    new_category = Category(name=name, description=description or "")
    db.session.add(new_category)
    db.session.commit()

    return jsonify({
        "msg": "Catégorie créée",
        "category": {
            "id": new_category.id,
            "name": new_category.name,
            "description": new_category.description
        }
    }), 201


# List all categories
@category_bp.route('/categories', methods=['GET'])
def get_categories():
    """
    Récupérer toutes les catégories

    tags:
        - categories
    responses:
        200:
            description: Liste des catégories récupérées
        404:
            description: Aucune catégorie trouvée
    """
    categories = Category.query.all()
    return jsonify({'categories': [
        {
            'id': c.id,
            'name': c.name,
            'description': c.description or ""
        } for c in categories
    ]}), 200


# Get specific category
@category_bp.route('/categories/<int:category_id>', methods=['GET'])
def get_category(category_id):
    """
    Récupérer une catégorie par son ID
    
    tags:
        - categories
    parameters:
        - in: path
          name: category_id
          required: true
          schema:
            type: integer
    responses:
        200:
            description: Catégorie récupérée
        404:
            description: Catégorie non trouvée
    """
    category = Category.query.get_or_404(category_id)
    return jsonify({
        'id': category.id,
        'name': category.name,
        'description': category.description or ""
    }), 200


# Update category
@category_bp.route('/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def update_category(category_id):
    """
    Mettre à jour une catégorie par son ID

    tags:
        - categories
    parameters:
        - in: path
          name: category_id
          required: true
          schema:
            type: integer
    responses:
        200:
            description: Catégorie mise à jour
        404:
            description: Catégorie non trouvée
    """
    err = _require_admin()
    if err:
        return err

    category = Category.query.get_or_404(category_id)
    data = request.get_json()

    category.name = data.get('name', category.name)
    category.description = data.get('description', category.description or "")
    db.session.commit()

    return jsonify({
        "msg": "Catégorie mise à jour",
        "category": {
            "id": category.id,
            "name": category.name,
            "description": category.description
        }
    }), 200


# Delete category
@category_bp.route('/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    """
    Supprimer une catégorie par son ID

    tags:
        - categories
    parameters:
        - in: path
          name: category_id
          required: true
          schema:
            type: integer
    responses:
        200:
            description: Catégorie supprimée
    """
    err = _require_admin()
    if err:
        return err

    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()

    return jsonify({"msg": "Catégorie supprimée"}), 200
