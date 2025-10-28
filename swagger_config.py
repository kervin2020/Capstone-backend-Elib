""" Configuration Swagger/openApi pour l'API E-LIB """

swagger_config = {
    "headers": [
    ],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,  # test   
            "model_filter": lambda tag: True,  # test
        },
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api/docs"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "E-Lib API - Système de Gestion de Bibliothèque",
        "description": """
        API REST complète pour la gestion d'une bibliothèque numérique.
        
        # Fonctionnalités
        -  Authentification JWT
        -  Gestion des utilisateurs
        -  Gestion des ebooks
        - Système d'emprunt (14 jours)
        - Catégories de livres
        
        # Authentification
        1. Créer un compte : `POST /api/users`
        2. Se connecter : `POST /api/login`
        3. Utiliser le token : `Authorization: Bearer <token>`
        
        # Compte Admin par défaut
        - Email : `admin@elib.com`
        - Password : `Admin@123`
        """,
        "version": "1.0.0",
        "contact": {
            "name": "Support E-Lib",
            "email": "support@elib.com"
        }
    },
    "host": "localhost:5000",
    "basePath": "/api",
    "schemes": ["http"],
    "securityDefinitions": {
        "jwt": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Token JWT au format: Bearer <token>"
        }
    },
    "tags": [
        {
            "name": "Authentification",
            "description": "Connexion et gestion des sessions"
        },
        {
            "name": "Utilisateurs",
            "description": "Gestion des comptes utilisateurs"
        },
        {
            "name": "Ebooks",
            "description": "Gestion de la bibliothèque de livres"
        },
        {
            "name": "Catégories",
            "description": "Gestion des catégories de livres"
        },
        {
            "name": "Emprunts",
            "description": "Système d'emprunt et de retour"
        }
    ]
}