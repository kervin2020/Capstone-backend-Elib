from app import create_app 
from config import db 
def init_database():
    app = create_app() with app.app_context():
    db.create_all()
    print("Database created successfully!") if __name__ == '__main__':
    init_database()
