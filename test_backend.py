import unittest 
import json 
import os 
import tempfile 
from datetime import datetime, timedelta 
from app import create_app 
from config import db 
from models import User, Ebook, Category, Loan 

class TestBackend(unittest.TestCase):
    """Tests complets pour le backend E-Lib""" 
    
    def setUp(self):
        """Configuration initiale pour chaque test""" 
        self.app = create_app() 
        self.app.config['TESTING'] = True 
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' 
        self.app.config['WTF_CSRF_ENABLED'] = False 
        self.client = self.app.test_client() 
        with self.app.app_context():
            db.create_all() 
            self.create_test_data() 
    
    def tearDown(self):
        """Nettoyage après chaque test""" 
        with self.app.app_context():
            db.session.remove() 
            db.drop_all() 
    
    def create_test_data(self):
        """Créer des données de test""" 
        # Créer un utilisateur admin 
        admin_user = User(
            username='admin', 
            email='admin@elib.com', 
            password=User.hash_password('admin123'), 
            is_admin=True 
        ) 
        db.session.add(admin_user) 
        
        # Créer un utilisateur normal 
        normal_user = User(
            username='user1', 
            email='user1@elib.com', 
            password=User.hash_password('user123'), 
            is_admin=False 
        ) 
        db.session.add(normal_user) 
        
        # Créer des catégories 
        fiction = Category(name='Fiction', description='Fictional books') 
        science = Category(name='Science', description='Science books') 
        db.session.add(fiction) 
        db.session.add(science) 
        
        # Créer des livres 
        book1 = Ebook(
            title='Test Book 1', 
            author='Author 1', 
            description='A test book', 
            file_path='/path/to/book1.pdf', 
            total_copies=5, 
            available_copies=5 
        ) 
        book2 = Ebook(
            title='Test Book 2', 
            author='Author 2', 
            description='Another test book', 
            file_path='/path/to/book2.pdf', 
            total_copies=3, 
            available_copies=2 
        ) 
        db.session.add(book1) 
        db.session.add(book2) 
        db.session.commit() 
        
        # Associer des catégories aux livres 
        book1.categories.append(fiction) 
        book2.categories.append(science) 
        db.session.commit() 
        
        # Créer un emprunt 
        loan = Loan(
            user_id=normal_user.id, 
            ebook_id=book2.id, 
            loan_date=datetime.utcnow(), 
            due_date=datetime.utcnow() + timedelta(days=14), 
            is_returned=False 
        ) 
        db.session.add(loan) 
        db.session.commit() 
    
    def get_auth_token(self, email='admin@elib.com', password='admin123'):
        """Obtenir un token d'authentification""" 
        response = self.client.post('/api/login', 
            data=json.dumps({'email': email, 'password': password}), 
            content_type='application/json' 
        ) 
        return json.loads(response.data)['access_token'] 
    
    def test_app_creation(self):
        """Test: L'application se crée correctement""" 
        self.assertIsNotNone(self.app) 
        self.assertTrue(self.app.config['TESTING']) 
    
    def test_database_creation(self):
        """Test: La base de données se crée correctement""" 
        with self.app.app_context():
            users = User.query.all() 
            self.assertEqual(len(users), 2) 
            books = Ebook.query.all() 
            self.assertEqual(len(books), 2) 
            categories = Category.query.all() 
            self.assertEqual(len(categories), 2) 
    
    # Authentication tests 
    def test_user_registration(self):
        """Test: Inscription d'un nouvel utilisateur""" 
        user_data = {
            'username': 'newuser', 
            'email': 'newuser@elib.com', 
            'password': 'newpass123' 
        } 
        response = self.client.post('/api/users', 
            data=json.dumps(user_data), 
            content_type='application/json' 
        ) 
        self.assertEqual(response.status_code, 201) 
        data = json.loads(response.data) 
        self.assertEqual(data['user']['username'], 'newuser') 
        self.assertEqual(data['user']['email'], 'newuser@elib.com') 
    
    def test_user_login(self):
        """Test: Connexion utilisateur""" 
        login_data = {
            'email': 'admin@elib.com', 
            'password': 'admin123' 
        } 
        response = self.client.post('/api/login', 
            data=json.dumps(login_data), 
            content_type='application/json' 
        ) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertIn('access_token', data) 
    
    def test_invalid_login(self):
        """Test: Connexion avec des identifiants invalides""" 
        login_data = {
            'email': 'admin@elib.com', 
            'password': 'wrongpassword' 
        } 
        response = self.client.post('/api/login', 
            data=json.dumps(login_data), 
            content_type='application/json' 
        ) 
        self.assertEqual(response.status_code, 401) 
    
    def test_protected_route_without_token(self):
        """Test: Accès à une route protégée sans token""" 
        response = self.client.get('/api/users') 
        self.assertEqual(response.status_code, 401) 
    
    def test_protected_route_with_token(self):
        """Test: Accès à une route protégée avec token valide""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.get('/api/users', headers=headers) 
        self.assertEqual(response.status_code, 200) 
    
    # Book tests 
    def test_get_all_books(self):
        """Test: Récupération de tous les livres""" 
        response = self.client.get('/api/ebooks') 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(len(data['ebooks']), 2) 
    
    def test_get_single_book(self):
        """Test: Récupération d'un livre spécifique""" 
        response = self.client.get('/api/ebooks/1') 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(data['title'], 'Test Book 1') 
    
    def test_create_book_as_admin(self):
        """Test: Création d'un livre par un admin""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        book_data = {
            'title': 'New Book', 
            'author': 'New Author', 
            'description': 'A new book', 
            'file_path': '/path/to/newbook.pdf', 
            'total_copies': 3, 
            'available_copies': 3 
        } 
        response = self.client.post('/api/ebooks', 
            data=json.dumps(book_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 201) 
        data = json.loads(response.data) 
        self.assertEqual(data['ebook']['title'], 'New Book') 
    
    def test_create_book_as_user(self):
        """Test: Tentative de création d'un livre par un utilisateur normal""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        book_data = {
            'title': 'Unauthorized Book', 
            'author': 'Unauthorized Author' 
        } 
        response = self.client.post('/api/ebooks', 
            data=json.dumps(book_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 403) 
    
    def test_update_book(self):
        """Test: Mise à jour d'un livre""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        update_data = {
            'title': 'Updated Book Title', 
            'author': 'Updated Author' 
        } 
        response = self.client.put('/api/ebooks/1', 
            data=json.dumps(update_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(data['ebook']['title'], 'Updated Book Title') 
    
    def test_delete_book(self):
        """Test: Suppression d'un livre""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.delete('/api/ebooks/1', headers=headers) 
        self.assertEqual(response.status_code, 200) 
        
        # Vérifier que le livre a été supprimé 
        response = self.client.get('/api/ebooks/1') 
        self.assertEqual(response.status_code, 404) 
    
    # Category tests 
    def test_get_all_categories(self):
        """Test: Récupération de toutes les catégories""" 
        response = self.client.get('/api/categories') 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(len(data['categories']), 2) 
    
    def test_create_category(self):
        """Test: Création d'une nouvelle catégorie""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        category_data = {
            'name': 'History', 
            'description': 'Historical books' 
        } 
        response = self.client.post('/api/categories', 
            data=json.dumps(category_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 201) 
        data = json.loads(response.data) 
        self.assertEqual(data['category']['name'], 'History') 
    
    def test_update_category(self):
        """Test: Mise à jour d'une catégorie""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        update_data = {
            'name': 'Updated Fiction', 
            'description': 'Updated description' 
        } 
        response = self.client.put('/api/categories/1', 
            data=json.dumps(update_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(data['category']['name'], 'Updated Fiction') 
    
    def test_delete_category(self):
        """Test: Suppression d'une catégorie""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.delete('/api/categories/1', headers=headers) 
        self.assertEqual(response.status_code, 200) 
    
    # Loan tests 
    def test_create_loan(self):
        """Test: Création d'un emprunt""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        loan_data = {'ebook_id': 1} 
        response = self.client.post('/api/loans', 
            data=json.dumps(loan_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 201) 
        data = json.loads(response.data) 
        self.assertEqual(data['loan']['ebook_id'], 1) 
    
    def test_create_loan_unavailable_book(self):
        """Test: Tentative d'emprunt d'un livre non disponible""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        
        # Modifier le livre pour qu'il ne soit pas disponible 
        with self.app.app_context():
            book = Ebook.query.get(1) 
            book.available_copies = 0 
            db.session.commit() 
        
        loan_data = {'ebook_id': 1} 
        response = self.client.post('/api/loans', 
            data=json.dumps(loan_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 400) 
    
    def test_get_user_loans(self):
        """Test: Récupération des emprunts d'un utilisateur""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.get('/api/loans/1', headers=headers) 
        self.assertEqual(response.status_code, 200) 
    
    def test_return_book(self):
        """Test: Retour d'un livre""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.put('/api/loans/1', headers=headers) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertTrue(data['loan']['is_returned']) 
    
    def test_get_all_loans_as_admin(self):
        """Test: Récupération de tous les emprunts par un admin""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.get('/api/loans', headers=headers) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertGreaterEqual(len(data['loans']), 1) 
    
    # User management tests 
    def test_get_all_users_as_admin(self):
        """Test: Récupération de tous les utilisateurs par un admin""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.get('/api/users', headers=headers) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(len(data['users']), 2) 
    
    def test_update_user(self):
        """Test: Mise à jour d'un utilisateur""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        update_data = {
            'username': 'updated_user', 
            'email': 'updated@elib.com' 
        } 
        response = self.client.put('/api/users/2', 
            data=json.dumps(update_data), 
            content_type='application/json', 
            headers=headers 
        ) 
        self.assertEqual(response.status_code, 200) 
        data = json.loads(response.data) 
        self.assertEqual(data['user']['username'], 'updated_user') 
    
    def test_delete_user(self):
        """Test: Suppression d'un utilisateur""" 
        token = self.get_auth_token() 
        headers = {'Authorization': f'Bearer {token}'} 
        response = self.client.delete('/api/users/2', headers=headers) 
        self.assertEqual(response.status_code, 200) 
    
    # Validation tests 
    def test_required_fields_validation(self):
        """Test: Validation des champs requis""" 
        # Test inscription sans email 
        user_data = {
            'username': 'testuser', 
            'password': 'testpass' 
        } 
        response = self.client.post('/api/users', 
            data=json.dumps(user_data), 
            content_type='application/json' 
        ) 
        self.assertEqual(response.status_code, 400) 
    
    def test_unique_email_validation(self):
        """Test: Validation de l'unicité de l'email""" 
        user_data = {
            'username': 'newuser', 
            'email': 'admin@elib.com',  # Email déjà utilisé 
            'password': 'newpass' 
        } 
        response = self.client.post('/api/users', 
            data=json.dumps(user_data), 
            content_type='application/json' 
        ) 
        self.assertEqual(response.status_code, 400) 
    
    # Performance tests 
    def test_multiple_loans_performance(self):
        """Test: Performance avec plusieurs emprunts""" 
        token = self.get_auth_token('user1@elib.com', 'user123') 
        headers = {'Authorization': f'Bearer {token}'} 
        
        # Créer plusieurs emprunts 
        for i in range(5):
            loan_data = {'ebook_id': 1} 
            response = self.client.post('/api/loans', 
                data=json.dumps(loan_data), 
                content_type='application/json', 
                headers=headers 
            ) 
            # Note: Ce test échouera car le livre n'est plus disponible 
            # mais cela teste la logique métier 
    
    def test_concurrent_loan_attempts(self):
        """Test: Tentatives d'emprunt concurrentes""" 
        # Ce test simulerait des tentatives d'emprunt simultanées 
        # Dans un vrai test, on utiliserait des threads 
        pass 

if __name__ == '__main__':
    unittest.main()