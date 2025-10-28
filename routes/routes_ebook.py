from config import db
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Ebook, User
from datetime import datetime

# Blueprint pour les routes ebook
ebook_bp = Blueprint('ebook_bp', __name__)


def _require_admin():
    """Vérifie si l'utilisateur est administrateur"""
    user = User.query.get(get_jwt_identity())
    if not user or not user.is_admin:
        return jsonify({"msg": "Accès interdit, vous n'êtes pas administrateur"}), 403
    return None


# Créer un ebook
@ebook_bp.route('/ebooks', methods=['POST'])
@jwt_required()
def create_ebook():
    err = _require_admin()
    if err:
        return err

    data = request.get_json()

    title = data.get('title')
    author = data.get('author')
    description = data.get('description', "")
    file_path = data.get('file_path')  # facultatif
    total_copies = data.get('total_copies', 1)
    available_copies = data.get('available_copies', total_copies)

    if not title:
        return jsonify({"msg": "Le titre est requis"}), 400

    try:
        new_ebook = Ebook(
            title=title,
            author=author,
            description=description,
            file_path=file_path,
            total_copies=total_copies,
            available_copies=available_copies,
            uploaded_at=datetime.utcnow()
        )

        db.session.add(new_ebook)
        db.session.commit()

        return jsonify({
            "msg": "Ebook créé avec succès",
            "ebook": {
                'id': new_ebook.id,
                'title': new_ebook.title,
                'author': new_ebook.author,
                'description': new_ebook.description,
                'file_path': new_ebook.file_path,
                'total_copies': new_ebook.total_copies,
                'available_copies': new_ebook.available_copies,
                'uploaded_at': new_ebook.uploaded_at
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        print("Erreur création ebook:", e)
        return jsonify({"msg": "Erreur interne du serveur"}), 500


# Récupérer tous les ebooks
@ebook_bp.route('/ebooks', methods=['GET'])
def get_ebooks():
    ebooks = Ebook.query.all()
    return jsonify({'ebooks': [
        {
            'id': ebook.id,
            'title': ebook.title,
            'author': ebook.author,
            'description': ebook.description,
            'file_path': ebook.file_path,
            'total_copies': ebook.total_copies,
            'available_copies': ebook.available_copies,
            'uploaded_at': ebook.uploaded_at
        } for ebook in ebooks
    ]}), 200


# Récupérer un ebook par ID
@ebook_bp.route('/ebooks/<int:ebook_id>', methods=['GET'])
def get_ebook(ebook_id):
    ebook = Ebook.query.get_or_404(ebook_id)
    return jsonify({
        'id': ebook.id,
        'title': ebook.title,
        'author': ebook.author,
        'description': ebook.description,
        'file_path': ebook.file_path,
        'total_copies': ebook.total_copies,
        'available_copies': ebook.available_copies,
        'uploaded_at': ebook.uploaded_at
    }), 200


# Mettre à jour un ebook
@ebook_bp.route('/ebooks/<int:ebook_id>', methods=['PUT'])
@jwt_required()
def update_ebook(ebook_id):
    err = _require_admin()
    if err:
        return err

    ebook = Ebook.query.get_or_404(ebook_id)
    data = request.get_json()

    ebook.title = data.get('title', ebook.title)
    ebook.author = data.get('author', ebook.author)
    ebook.description = data.get('description', ebook.description)
    ebook.file_path = data.get('file_path', ebook.file_path)
    ebook.total_copies = data.get('total_copies', ebook.total_copies)
    ebook.available_copies = data.get(
        'available_copies', ebook.available_copies)
    ebook.uploaded_at = data.get('uploaded_at', ebook.uploaded_at)

    try:
        db.session.commit()
        return jsonify({
            "msg": "Ebook mis à jour avec succès",
            "ebook": {
                'id': ebook.id,
                'title': ebook.title,
                'author': ebook.author,
                'description': ebook.description,
                'file_path': ebook.file_path,
                'total_copies': ebook.total_copies,
                'available_copies': ebook.available_copies,
                'uploaded_at': ebook.uploaded_at
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        print("Erreur mise à jour ebook:", e)
        return jsonify({"msg": "Erreur interne du serveur"}), 500


# Supprimer un ebook
@ebook_bp.route('/ebooks/<int:ebook_id>', methods=['DELETE'])
@jwt_required()
def delete_ebook(ebook_id):
    err = _require_admin()
    if err:
        return err

    ebook = Ebook.query.get_or_404(ebook_id)

    try:
        db.session.delete(ebook)
        db.session.commit()
        return jsonify({"msg": "Ebook supprimé avec succès"}), 200
    except Exception as e:
        db.session.rollback()
        print("Erreur suppression ebook:", e)
        return jsonify({"msg": "Erreur interne du serveur"}), 500
