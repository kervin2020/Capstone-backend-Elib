#!/usr/bin/env python3
"""
Script pour exécuter tous les tests du backend E-Lib
"""
import unittest
import sys
import os
import subprocess
from io import StringIO

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_backend_tests():
    """Exécuter les tests backend"""
    print("Execution des tests backend...")
    print("=" * 50)
    
    # Créer un test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName('test_backend')
    
    # Exécuter les tests avec un buffer pour capturer la sortie
    stream = StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    
    # Afficher les résultats
    print(stream.getvalue())
    
    # Résumé
    print("\n" + "=" * 50)
    print(f"Tests reussis: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Tests echoues: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Total: {result.testsRun}")
    
    if result.failures:
        print("\nECHECS:")
        for test, traceback in result.failures:
            print(f" - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\nERREURS:")
        for test, traceback in result.errors:
            print(f" - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    return result.wasSuccessful()


def check_backend_requirements():
    """Vérifier que tous les modules requis sont installés"""
    print("Verification des dependances backend...")
    required_modules = [
        'flask', 'flask_sqlalchemy', 'flask_jwt_extended', 
        'flask_cors', 'flask_bcrypt', 'flask_migrate'
    ]
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f" OK {module}")
        except ImportError:
            missing_modules.append(module)
            print(f" MANQUANT {module}")
    
    if missing_modules:
        print(f"\nModules manquants: {', '.join(missing_modules)}")
        print("Installez-les avec: pip install " + " ".join(missing_modules))
        return False
    
    print("Toutes les dependances sont installees")
    return True


def test_database_connection():
    """Tester la connexion à la base de données"""
    print("\nTest de connexion a la base de donnees...")
    try:
        from app import create_app
        from config import db
        
        app = create_app()
        with app.app_context():
            # Tenter de créer les tables
            db.create_all()
            print(" Connexion a la base de donnees reussie")
            print(" Tables creees avec succes")
            
            # Nettoyer
            db.drop_all()
            print(" Nettoyage effectue")
        
        return True
    except Exception as e:
        print(f" Erreur de connexion a la base de donnees: {e}")
        return False


def test_api_endpoints():
    """Tester les endpoints API de base"""
    print("\nTest des endpoints API...")
    try:
        from app import create_app
        
        app = create_app()
        client = app.test_client()
        
        # Test de l'endpoint racine
        response = client.get('/')
        if response.status_code == 200:
            print(" Endpoint racine accessible")
        else:
            print(f" Endpoint racine: {response.status_code}")
            return False
        
        # Test de l'endpoint des livres (sans auth)
        response = client.get('/api/ebooks')
        if response.status_code == 200:
            print(" Endpoint des livres accessible")
        else:
            print(f" Endpoint des livres: {response.status_code}")
            return False
        
        # Test de l'endpoint des catégories
        response = client.get('/api/categories')
        if response.status_code == 200:
            print(" Endpoint des categories accessible")
        else:
            print(f" Endpoint des categories: {response.status_code}")
            return False
        
        return True
    except Exception as e:
        print(f" Erreur lors du test des endpoints: {e}")
        return False


def main():
    """Fonction principale"""
    print("DEMARRAGE DES TESTS BACKEND E-LIB")
    print("=" * 60)
    
    # Vérifier les dépendances
    if not check_backend_requirements():
        print("\nTests annules: dependances manquantes")
        return False
    
    # Tester la connexion à la base de données
    if not test_database_connection():
        print("\nTests annules: probleme de base de donnees")
        return False
    
    # Tester les endpoints API
    if not test_api_endpoints():
        print("\nTests annules: probleme d'API")
        return False
    
    # Exécuter les tests unitaires
    print("\nExecution des tests unitaires...")
    success = run_backend_tests()
    
    # Résumé final
    print("\n" + "=" * 60)
    if success:
        print("TOUS LES TESTS BACKEND SONT PASSES!")
        print("Le backend est pret pour la production")
    else:
        print("CERTAINS TESTS ONT ECHOUE")
        print("Veuillez corriger les erreurs avant de continuer")
    
    return success


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)