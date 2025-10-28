from app import create_app
from config import db
from models import User, Category, Ebook
from datetime import datetime

# Create the Flask app context
app = create_app()

print("=== 🚀 Starting database seeding ===")

with app.app_context():
    # Reset the database
    print("🧹 Dropping and recreating all tables...")
    db.drop_all()
    db.create_all()

    # Create admin user
    print("👤 Creating admin user...")
    admin = User(
        username="admin",
        email="admin@example.com",
        password=User.hash_password("admin123"),
        is_admin=True
    )
    db.session.add(admin)

    # Create categories
    print("📚 Creating categories...")
    categories = [
        Category(name="Informatique",
                 description="Livres sur la programmation et la technologie."),
        Category(name="Science",
                 description="Livres de physique, chimie et biologie."),
        Category(name="Littérature",
                 description="Romans et œuvres littéraires."),
        Category(name="Éducation",
                 description="Livres éducatifs pour tous les âges.")
    ]
    db.session.add_all(categories)
    db.session.commit()  # Commit to get IDs

    # Create sample ebooks
    print("📘 Creating ebooks...")
    ebooks = [
        Ebook(
            title="Apprendre Python",
            author="Guido van Rossum",
            description="Un guide complet pour apprendre Python.",
            cover_image="uploads/covers/apprendre_python.jpg",
            file_path="uploads/apprendre_python.pdf",
            total_copies=5,
            available_copies=5,
            categories=[categories[0], categories[3]]
        ),
        Ebook(
            title="Introduction à la Physique",
            author="Marie Curie",
            description="Concepts fondamentaux de la physique moderne.",
            cover_image="uploads/covers/apprendre_python.jpg",
            file_path="uploads/physique.pdf",
            total_copies=3,
            available_copies=3,
            categories=[categories[1]]
        ),
        Ebook(
            title="Les Misérables",
            author="Victor Hugo",
            description="Un classique de la littérature française.",
            cover_image="uploads/covers/apprendre_python.jpg",
            file_path="uploads/les_miserables.pdf",
            total_copies=2,
            available_copies=2,
            categories=[categories[2]]
        ),
    ]
    db.session.add_all(ebooks)
    db.session.commit()

    print("✅ Database seeding completed successfully!")
