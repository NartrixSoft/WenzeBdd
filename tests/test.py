import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from rest_framework import status

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def create_user(db):
    def make_user(**kwargs):
        return get_user_model().objects.create_user(**kwargs)
    return make_user

@pytest.fixture
def user(create_user):
    return create_user(username="testuser", password="testpass123")

@pytest.fixture
def auth_client(api_client, user):
    api_client.force_authenticate(user=user)
    return api_client

def test_signup(api_client):
    data = {
        "username": "newuser",
        "password": "newpass123",
        "email": "newuser@example.com"
    }
    response = api_client.post("/api/signup/", data)
    assert response.status_code == status.HTTP_201_CREATED

def test_login(api_client, user):
    data = {
        "username": "testuser",
        "password": "testpass123"
    }
    response = api_client.post("/api/login/", data)
    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh" in response.data

def test_get_products(api_client):
    response = api_client.get("/api/products/")
    assert response.status_code == status.HTTP_200_OK

def test_create_product(auth_client):
    data = {
        "name": "Test Product",
        "description": "A sample product",
        "price": "10.99",
        "available": True
    }
    response = auth_client.post("/api/products/", data)
    assert response.status_code == status.HTTP_201_CREATED
