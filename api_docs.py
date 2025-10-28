"""
API Documentation for E-Lib Backend
This module provides Swagger/OpenAPI documentation for all API endpoints
"""

from flask import Blueprint
from flask_restx import Api, Resource, fields
from models import User, Ebook, Category, Loan

# Create API blueprint
api_bp = Blueprint('api_docs', __name__)

# Initialize Flask-RESTX API
api = Api(
    api_bp,
    version='1.0',
    title='E-Lib API',
    description='A comprehensive digital library management system API',
    doc='/docs/',  # Swagger UI will be available at /docs/
    prefix='/api'
)

# Define namespaces
user_ns = api.namespace('users', description='User management operations')
ebook_ns = api.namespace('ebooks', description='E-book management operations')
category_ns = api.namespace('categories', description='Category management operations')
loan_ns = api.namespace('loans', description='Loan management operations')

# Define models for request/response documentation
user_model = api.model('User', {
    'id': fields.Integer(description='User ID'),
    'username': fields.String(required=True, description='Username'),
    'email': fields.String(required=True, description='Email address'),
    'is_admin': fields.Boolean(description='Admin status'),
    'created_at': fields.DateTime(description='Creation date')
})

user_create_model = api.model('UserCreate', {
    'username': fields.String(required=True, description='Username'),
    'email': fields.String(required=True, description='Email address'),
    'password': fields.String(required=True, description='Password'),
    'is_admin': fields.Boolean(description='Admin status', default=False)
})

user_update_model = api.model('UserUpdate', {
    'username': fields.String(description='Username'),
    'email': fields.String(description='Email address'),
    'password': fields.String(description='Password'),
    'is_admin': fields.Boolean(description='Admin status')
})

login_model = api.model('Login', {
    'email': fields.String(required=True, description='Email address'),
    'password': fields.String(required=True, description='Password')
})

ebook_model = api.model('Ebook', {
    'id': fields.Integer(description='Ebook ID'),
    'title': fields.String(required=True, description='Book title'),
    'author': fields.String(description='Author name'),
    'description': fields.String(description='Book description'),
    'file_path': fields.String(required=True, description='File path'),
    'total_copies': fields.Integer(description='Total copies available'),
    'available_copies': fields.Integer(description='Available copies'),
    'uploaded_at': fields.DateTime(description='Upload date')
})

ebook_create_model = api.model('EbookCreate', {
    'title': fields.String(required=True, description='Book title'),
    'author': fields.String(description='Author name'),
    'description': fields.String(description='Book description'),
    'file_path': fields.String(required=True, description='File path'),
    'total_copies': fields.Integer(description='Total copies available', default=1),
    'available_copies': fields.Integer(description='Available copies', default=1)
})

ebook_update_model = api.model('EbookUpdate', {
    'title': fields.String(description='Book title'),
    'author': fields.String(description='Author name'),
    'description': fields.String(description='Book description'),
    'file_path': fields.String(description='File path'),
    'total_copies': fields.Integer(description='Total copies available'),
    'available_copies': fields.Integer(description='Available copies')
})

category_model = api.model('Category', {
    'id': fields.Integer(description='Category ID'),
    'name': fields.String(required=True, description='Category name'),
    'description': fields.String(description='Category description')
})

category_create_model = api.model('CategoryCreate', {
    'name': fields.String(required=True, description='Category name'),
    'description': fields.String(description='Category description')
})

category_update_model = api.model('CategoryUpdate', {
    'name': fields.String(description='Category name'),
    'description': fields.String(description='Category description')
})

loan_model = api.model('Loan', {
    'id': fields.Integer(description='Loan ID'),
    'user_id': fields.Integer(description='User ID'),
    'ebook_id': fields.Integer(description='Ebook ID'),
    'loan_date': fields.DateTime(description='Loan date'),
    'due_date': fields.DateTime(description='Due date'),
    'return_date': fields.DateTime(description='Return date'),
    'is_returned': fields.Boolean(description='Return status')
})

loan_create_model = api.model('LoanCreate', {
    'ebook_id': fields.Integer(required=True, description='Ebook ID to borrow')
})

# Response models
success_response = api.model('SuccessResponse', {
    'msg': fields.String(description='Success message'),
    'data': fields.Raw(description='Response data')
})

error_response = api.model('ErrorResponse', {
    'msg': fields.String(description='Error message')
})

# User endpoints documentation
@user_ns.route('/')
class UserList(Resource):
    @user_ns.doc('get_users')
    @user_ns.marshal_list_with(user_model)
    @user_ns.response(200, 'Success', user_model)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(403, 'Forbidden', error_response)
    def get(self):
        """Get all users (Admin only)"""
        pass

    @user_ns.doc('create_user')
    @user_ns.expect(user_create_model)
    @user_ns.marshal_with(success_response, code=201)
    @user_ns.response(201, 'User created', success_response)
    @user_ns.response(400, 'Bad request', error_response)
    def post(self):
        """Create a new user"""
        pass

@user_ns.route('/<int:user_id>')
class User(Resource):
    @user_ns.doc('get_user')
    @user_ns.marshal_with(user_model)
    @user_ns.response(200, 'Success', user_model)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(403, 'Forbidden', error_response)
    @user_ns.response(404, 'User not found', error_response)
    def get(self, user_id):
        """Get user by ID"""
        pass

    @user_ns.doc('update_user')
    @user_ns.expect(user_update_model)
    @user_ns.marshal_with(success_response)
    @user_ns.response(200, 'User updated', success_response)
    @user_ns.response(400, 'Bad request', error_response)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(403, 'Forbidden', error_response)
    @user_ns.response(404, 'User not found', error_response)
    def put(self, user_id):
        """Update user by ID"""
        pass

    @user_ns.doc('delete_user')
    @user_ns.marshal_with(success_response)
    @user_ns.response(200, 'User deleted', success_response)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(403, 'Forbidden', error_response)
    @user_ns.response(404, 'User not found', error_response)
    def delete(self, user_id):
        """Delete user by ID"""
        pass

@user_ns.route('/me')
class CurrentUser(Resource):
    @user_ns.doc('get_current_user')
    @user_ns.marshal_with(user_model)
    @user_ns.response(200, 'Success', user_model)
    @user_ns.response(401, 'Unauthorized', error_response)
    def get(self):
        """Get current user information"""
        pass

@user_ns.route('/login')
class Login(Resource):
    @user_ns.doc('login')
    @user_ns.expect(login_model)
    @user_ns.response(200, 'Login successful', {'access_token': fields.String()})
    @user_ns.response(400, 'Bad request', error_response)
    @user_ns.response(401, 'Invalid credentials', error_response)
    def post(self):
        """User login"""
        pass

# Ebook endpoints documentation
@ebook_ns.route('/')
class EbookList(Resource):
    @ebook_ns.doc('get_ebooks')
    @ebook_ns.marshal_list_with(ebook_model)
    @ebook_ns.response(200, 'Success', [ebook_model])
    def get(self):
        """Get all ebooks"""
        pass

    @ebook_ns.doc('create_ebook')
    @ebook_ns.expect(ebook_create_model)
    @ebook_ns.marshal_with(success_response, code=201)
    @ebook_ns.response(201, 'Ebook created', success_response)
    @ebook_ns.response(400, 'Bad request', error_response)
    @ebook_ns.response(401, 'Unauthorized', error_response)
    @ebook_ns.response(403, 'Forbidden', error_response)
    def post(self):
        """Create a new ebook (Admin only)"""
        pass

@ebook_ns.route('/<int:ebook_id>')
class Ebook(Resource):
    @ebook_ns.doc('get_ebook')
    @ebook_ns.marshal_with(ebook_model)
    @ebook_ns.response(200, 'Success', ebook_model)
    @ebook_ns.response(404, 'Ebook not found', error_response)
    def get(self, ebook_id):
        """Get ebook by ID"""
        pass

    @ebook_ns.doc('update_ebook')
    @ebook_ns.expect(ebook_update_model)
    @ebook_ns.marshal_with(success_response)
    @ebook_ns.response(200, 'Ebook updated', success_response)
    @ebook_ns.response(400, 'Bad request', error_response)
    @ebook_ns.response(401, 'Unauthorized', error_response)
    @ebook_ns.response(403, 'Forbidden', error_response)
    @ebook_ns.response(404, 'Ebook not found', error_response)
    def put(self, ebook_id):
        """Update ebook by ID (Admin only)"""
        pass

    @ebook_ns.doc('delete_ebook')
    @ebook_ns.marshal_with(success_response)
    @ebook_ns.response(200, 'Ebook deleted', success_response)
    @ebook_ns.response(401, 'Unauthorized', error_response)
    @ebook_ns.response(403, 'Forbidden', error_response)
    @ebook_ns.response(404, 'Ebook not found', error_response)
    def delete(self, ebook_id):
        """Delete ebook by ID (Admin only)"""
        pass

# Category endpoints documentation
@category_ns.route('/')
class CategoryList(Resource):
    @category_ns.doc('get_categories')
    @category_ns.marshal_list_with(category_model)
    @category_ns.response(200, 'Success', [category_model])
    def get(self):
        """Get all categories"""
        pass

    @category_ns.doc('create_category')
    @category_ns.expect(category_create_model)
    @category_ns.marshal_with(success_response, code=201)
    @category_ns.response(201, 'Category created', success_response)
    @category_ns.response(400, 'Bad request', error_response)
    @category_ns.response(401, 'Unauthorized', error_response)
    @category_ns.response(403, 'Forbidden', error_response)
    def post(self):
        """Create a new category (Admin only)"""
        pass

@category_ns.route('/<int:category_id>')
class Category(Resource):
    @category_ns.doc('get_category')
    @category_ns.marshal_with(category_model)
    @category_ns.response(200, 'Success', category_model)
    @category_ns.response(404, 'Category not found', error_response)
    def get(self, category_id):
        """Get category by ID"""
        pass

    @category_ns.doc('update_category')
    @category_ns.expect(category_update_model)
    @category_ns.marshal_with(success_response)
    @category_ns.response(200, 'Category updated', success_response)
    @category_ns.response(400, 'Bad request', error_response)
    @category_ns.response(401, 'Unauthorized', error_response)
    @category_ns.response(403, 'Forbidden', error_response)
    @category_ns.response(404, 'Category not found', error_response)
    def put(self, category_id):
        """Update category by ID (Admin only)"""
        pass

    @category_ns.doc('delete_category')
    @category_ns.marshal_with(success_response)
    @category_ns.response(200, 'Category deleted', success_response)
    @category_ns.response(401, 'Unauthorized', error_response)
    @category_ns.response(403, 'Forbidden', error_response)
    @category_ns.response(404, 'Category not found', error_response)
    def delete(self, category_id):
        """Delete category by ID (Admin only)"""
        pass

# Loan endpoints documentation
@loan_ns.route('/')
class LoanList(Resource):
    @loan_ns.doc('get_loans')
    @loan_ns.marshal_list_with(loan_model)
    @loan_ns.response(200, 'Success', [loan_model])
    @loan_ns.response(401, 'Unauthorized', error_response)
    def get(self):
        """Get all loans (Admin) or user's loans"""
        pass

    @loan_ns.doc('create_loan')
    @loan_ns.expect(loan_create_model)
    @loan_ns.marshal_with(success_response, code=201)
    @loan_ns.response(201, 'Loan created', success_response)
    @loan_ns.response(400, 'Bad request', error_response)
    @loan_ns.response(401, 'Unauthorized', error_response)
    def post(self):
        """Create a new loan"""
        pass

@loan_ns.route('/<int:loan_id>')
class Loan(Resource):
    @loan_ns.doc('get_loan')
    @loan_ns.marshal_with(loan_model)
    @loan_ns.response(200, 'Success', loan_model)
    @loan_ns.response(401, 'Unauthorized', error_response)
    @loan_ns.response(403, 'Forbidden', error_response)
    @loan_ns.response(404, 'Loan not found', error_response)
    def get(self, loan_id):
        """Get loan by ID"""
        pass

    @loan_ns.doc('update_loan')
    @loan_ns.marshal_with(success_response)
    @loan_ns.response(200, 'Loan updated', success_response)
    @loan_ns.response(400, 'Bad request', error_response)
    @loan_ns.response(401, 'Unauthorized', error_response)
    @loan_ns.response(403, 'Forbidden', error_response)
    @loan_ns.response(404, 'Loan not found', error_response)
    def put(self, loan_id):
        """Return a book (update loan status)"""
        pass

    @loan_ns.doc('delete_loan')
    @loan_ns.marshal_with(success_response)
    @loan_ns.response(200, 'Loan deleted', success_response)
    @loan_ns.response(401, 'Unauthorized', error_response)
    @loan_ns.response(403, 'Forbidden', error_response)
    @loan_ns.response(404, 'Loan not found', error_response)
    def delete(self, loan_id):
        """Delete loan by ID (Admin only)"""
        pass

@loan_ns.route('/users/<int:user_id>')
class UserLoans(Resource):
    @loan_ns.doc('get_user_loans')
    @loan_ns.marshal_list_with(loan_model)
    @loan_ns.response(200, 'Success', [loan_model])
    @loan_ns.response(401, 'Unauthorized', error_response)
    @loan_ns.response(403, 'Forbidden', error_response)
    def get(self, user_id):
        """Get loans for a specific user"""
        pass
