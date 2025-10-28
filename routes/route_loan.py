from flask import Blueprint, request, jsonify
from models import Ebook, User, Loan
from config import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta

loan_bp = Blueprint('loan_bp', __name__)


# Check if user is admin
def _require_admin():
    """
    Vérifie si l'utilisateur est administrateur
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


# Create loan
@loan_bp.route('/loans', methods=['POST'])
@jwt_required()
def create_loan():
    """
    creer un nouvel emprunt

    tags:
      - loans
    security:
      - jwt: []
    parameters:
      - in: body
        name: loan
        schema:
            type: object
            properties:
              ebook_id:
                type: integer
            required:
              - ebook_id
    responses:
        201:
            description: Emprunt créé avec succès
        400:
            description: L'identifiant du livre est requis / Aucune copie disponible pour ce livre  

    
    """
    data = request.get_json()
    user_id = get_jwt_identity()

    if not data.get('ebook_id'):
        return jsonify({"msg": "L'identifiant du livre est requis"}), 400

    ebook = Ebook.query.get_or_404(data['ebook_id'])

    if ebook.available_copies < 1:
        return jsonify({"msg": "Aucune copie disponible pour ce livre"}), 400

    new_loan = Loan(
        user_id=user_id,
        ebook_id=ebook.id,
        loan_date=datetime.utcnow(),
        due_date=datetime.utcnow() + timedelta(days=14)
    )

    ebook.available_copies -= 1
    db.session.add(new_loan)
    db.session.commit()

    return jsonify({
        "msg": "Emprunt créé avec succès",
        "loan": {
            'id': new_loan.id,
            'user_id': new_loan.user_id,
            'ebook_id': new_loan.ebook_id,
            'loan_date': new_loan.loan_date,
            'due_date': new_loan.due_date
        }
    }), 201


# Get all loans
@loan_bp.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    """
    Récupérer tous les prêts

    tags:
        - loans
    responses:
        200:
            description: Liste des prêts récupérés
    """ 
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # Si l'utilisateur est admin, afficher tous les prêts
    if user.is_admin:
        loans = Loan.query.all()
    else:
        # Sinon, afficher seulement les prêts de l'utilisateur
        loans = Loan.query.filter_by(user_id=user_id).all()

    return jsonify({'loans': [
        {
            'id': loan.id,
            'user_id': loan.user_id,
            'ebook_id': loan.ebook_id,
            'loan_date': loan.loan_date,
            'due_date': loan.due_date,
            'return_date': loan.return_date,
            'is_returned': loan.is_returned
        } for loan in loans
    ]}), 200


# Get specific loan
@loan_bp.route('/loans/<int:loan_id>', methods=['GET'])
@jwt_required()
def get_loan(loan_id):
    """
    Récupérer un prêt par son ID

    tags:
        - loans 
    parameters:
        - in: path
          name: loan_id
          required: true
          schema:
            type: integer
    responses:
        200:
            description: prêt récupéré
    """
    loan = Loan.query.get_or_404(loan_id)
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user.is_admin and loan.user_id != user_id:
        return jsonify({"msg": "Accès interdit"}), 403

    return jsonify({
        'id': loan.id,
        'user_id': loan.user_id,
        'ebook_id': loan.ebook_id,
        'loan_date': loan.loan_date,
        'due_date': loan.due_date,
        'return_date': loan.return_date,
        'is_returned': loan.is_returned
    }), 200


# Update loan (return)
@loan_bp.route('/loans/<int:loan_id>', methods=['PUT'])
@jwt_required()
def update_loan(loan_id):
    """
    retourner un prêt

    tags:
        - loans
        security:
          - jwt: []
            parameters:
              - in: path
                name: loan_id
                required: true
                schema:
                  type: integer
            responses:
                200:
                    description: prêt retourné avec succès
                403:
                    description: Accès interdit, vous n'êtes pas propriétaire de ce prêt
                400:
                    description: Ce prêt a déjà été retourné
    """
    loan = Loan.query.get_or_404(loan_id)

    if loan.user_id != get_jwt_identity():
        return jsonify({"msg": "Accès interdit, vous n'êtes pas propriétaire de ce prêt"}), 403

    if loan.is_returned:
        return jsonify({"msg": "Ce prêt a déjà été retourné"}), 400

    loan.is_returned = True
    loan.return_date = datetime.utcnow()
    loan.ebook.available_copies += 1
    db.session.commit()

    return jsonify({
        "msg": f"Prêt du livre {loan.ebook.title} retourné avec succès",
        "loan": {
            'id': loan.id,
            'return_date': loan.return_date,
            'is_returned': loan.is_returned
        }
    }), 200


# Get user loans
@loan_bp.route('/users/<int:user_id>/loans', methods=['GET'])
@jwt_required()
def get_user_loans(user_id):
    """
    Récupérer les prêts d'un utilisateur
    
    tags:
        - loans
    parameters:
        - in: path
          name: user_id
          required: true
          schema:
            type: integer
    responses:
        200:
            description: Liste des prêts de l'utilisateur récupérée
    """
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Vérifier si l'utilisateur peut accéder à ces prêts
    if not current_user.is_admin and current_user_id != user_id:
        return jsonify({"msg": "Accès interdit"}), 403

    loans = Loan.query.filter_by(user_id=user_id).all()
    return jsonify({'loans': [
        {
            'id': loan.id,
            'user_id': loan.user_id,
            'ebook_id': loan.ebook_id,
            'loan_date': loan.loan_date,
            'due_date': loan.due_date,
            'return_date': loan.return_date,
            'is_returned': loan.is_returned
        } for loan in loans
    ]}), 200


# Delete loan
@loan_bp.route('/loans/<int:loan_id>', methods=['DELETE'])
@jwt_required()
def delete_loan(loan_id):
    """
    Supprimer un prêt

    tags:
        - loans

        parameters:
        - in: path
          name: loan_id
          required: true
          schema:
            type: integer
            responses:
                200:
                    description: prêt supprimé avec succès

    """
    err = _require_admin()
    if err:
        return err

    loan = Loan.query.get_or_404(loan_id)
    db.session.delete(loan)
    db.session.commit()

    return jsonify({"msg": "Prêt supprimé avec succès"}), 200
