from config import db
from flask_jwt_extended import get_jwt_identity
from datetime import datetime

# table d association entre les livre et categories
ebook_category = db.Table('ebook_category',
                          db.Column('ebook_id', db.Integer,
                                    db.ForeignKey('ebooks.id')),
                          db.Column('category_id', db.Integer,
                                    db.ForeignKey('categories.id'))
                          )

# Creation des models(tables)

# hmmm c est un model pour l'utilisateur


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    # contien hash c est a dire mot de passe non chiffre
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # relation one to many entre user et loan
    loans = db.relationship('Loan', back_populates='user', lazy=True)

    @staticmethod
    def current_is_admin(user_id=None):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return False
        if user_id is None:
            return user.is_admin
        return user.is_admin or current_user_id == user_id

    # Hash  un mot de passe
    @staticmethod
    def hash_password(password):
        from config import bcrypt
        return bcrypt.generate_password_hash(password).decode('utf-8')

    # verifier un mot de passe
    @staticmethod
    def check_password(password, hashed_password):
        from config import bcrypt
        return bcrypt.check_password_hash(hashed_password, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Ebook(db.Model):
    __tablename__ = 'ebooks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(40))
    author = db.Column(db.String(70))
    description = db.Column(db.Text)
    cover_image = db.Column(db.String(200), nullable=True)
    # chemin du fichier ebook
    file_path = db.Column(db.String(200), nullable=True)
    # nomvre total d'exemplaire
    total_copies = db.Column(db.Integer, default=1)
    # nombre d'exemplaire disponible
    available_copies = db.Column(db.Integer, default=1)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    categories = db.relationship('Category', secondary=ebook_category,
                                 # relation many to many entre ebook et category
                                 backref=db.backref('ebooks', lazy='dynamic'))
    # relation one to many entre ebook et loan
    loans = db.relationship('Loan', back_populates='ebook', lazy=True)

    def __repr__(self):
        return f'<Ebook {self.title} by {self.author}>'


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)

    def __repr__(self):
        return f'<Category {self.name}>'


class Loan(db.Model):
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ebook_id = db.Column(db.Integer, db.ForeignKey(
        'ebooks.id'), nullable=False)
    loan_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime, nullable=False)
    return_date = db.Column(db.DateTime, nullable=True)
    is_returned = db.Column(db.Boolean, default=False)

    # relation one to many entre user et loan
    user = db.relationship('User', back_populates='loans')
    # relation one to many entre ebook et loan
    ebook = db.relationship('Ebook', back_populates='loans')

    def __repr__(self):
        return f'<Loan User {self.user_id} - Ebook {self.ebook_id}>'
