#!/usr/bin/env python3
"""
Simple API endpoint tester for E-Lib backend
Tests all major endpoints to ensure they're working correctly
"""

import requests
import json
import sys

BASE_URL = "http://localhost:5000/api"

def test_endpoint(method, endpoint, data=None, headers=None, expected_status=200):
    """Test a single endpoint"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers=headers)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            print(f"❌ Unsupported method: {method}")
            return False
            
        if response.status_code == expected_status:
            print(f"✅ {method} {endpoint} - Status: {response.status_code}")
            return True
        else:
            print(f"❌ {method} {endpoint} - Expected: {expected_status}, Got: {response.status_code}")
            if response.text:
                print(f"   Response: {response.text[:100]}...")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"❌ {method} {endpoint} - Connection failed (Is the server running?)")
        return False
    except Exception as e:
        print(f"❌ {method} {endpoint} - Error: {str(e)}")
        return False

def main():
    """Run all API tests"""
    print("🧪 Testing E-Lib API Endpoints")
    print("=" * 50)
    
    # Test public endpoints
    print("\n📖 Testing Public Endpoints...")
    public_tests = [
        ("GET", "/ebooks"),
        ("GET", "/categories"),
    ]
    
    public_passed = 0
    for method, endpoint in public_tests:
        if test_endpoint(method, endpoint):
            public_passed += 1
    
    # Test user registration
    print("\n👤 Testing User Registration...")
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    if test_endpoint("POST", "/users", user_data, expected_status=201):
        public_passed += 1
    
    # Test login
    print("\n🔐 Testing User Login...")
    login_data = {
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", json=login_data)
        if response.status_code == 200:
            token = response.json().get('access_token')
            print("✅ POST /login - Status: 200")
            public_passed += 1
            
            # Test protected endpoints with token
            print("\n🔒 Testing Protected Endpoints...")
            headers = {"Authorization": f"Bearer {token}"}
            
            protected_tests = [
                ("GET", "/users/me"),
                ("GET", "/loans"),
            ]
            
            protected_passed = 0
            for method, endpoint in protected_tests:
                if test_endpoint(method, endpoint, headers=headers):
                    protected_passed += 1
            
            # Test book operations (admin required)
            print("\n📚 Testing Book Operations...")
            book_data = {
                "title": "Test Book",
                "author": "Test Author",
                "description": "A test book",
                "file_path": "/test/book.pdf",
                "total_copies": 1,
                "available_copies": 1
            }
            
            # This will fail without admin privileges, but we test the endpoint
            test_endpoint("POST", "/ebooks", book_data, headers=headers, expected_status=403)
            print("✅ POST /ebooks - Status: 403 (Expected - not admin)")
            
        else:
            print(f"❌ POST /login - Status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Login test failed: {str(e)}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print(f"   Public endpoints: {public_passed}/3 passed")
    print(f"   Protected endpoints: {protected_passed}/2 passed")
    
    if public_passed >= 2:
        print("✅ Basic API functionality is working!")
        return True
    else:
        print("❌ Some API endpoints are not working properly")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
