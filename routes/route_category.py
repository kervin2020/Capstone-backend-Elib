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
    Créer une nouvelle catégorie (Admin requis)
    ---
    tags:
      - Catégories
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
          properties:
            name:
              type: string
              description: Nom de la catégorie.
            description:
              type: string
              description: Description de la catégorie.
    responses:
      201:
        description: Catégorie créée avec succès.
      400:
        description: Données d'entrée invalides.
      403:
        description: Accès non autorisé (admin requis).
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
    Lister toutes les catégories
    ---
    tags:
      - Catégories
    responses:
      200:
        description: Une liste de toutes les catégories.
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
    Obtenir les détails d'une catégorie
    ---
    tags:
      - Catégories
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Détails de la catégorie.
      404:
        description: Catégorie non trouvée.
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
    Mettre à jour une catégorie (Admin requis)
    ---
    tags:
      - Catégories
    security:
      - Bearer: []
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
    responses:
      200:
        description: Catégorie mise à jour avec succès.
      403:
        description: Accès non autorisé (admin requis).
      404:
        description: Catégorie non trouvée.
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
    Supprimer une catégorie (Admin requis)
    ---
    tags:
      - Catégories
    security:
      - Bearer: []
    parameters:
      - name: category_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Catégorie supprimée avec succès.
      403:
        description: Accès non autorisé (admin requis).
      404:
        description: Catégorie non trouvée.
    """
    err = _require_admin()
    if err:
        return err

    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()

    return jsonify({"msg": "Catégorie supprimée"}), 200
