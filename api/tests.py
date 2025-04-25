import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from api.models import Store, Product

User = get_user_model()

@pytest.mark.django_db
def test_product_has_no_store_when_none_specified():
    """
    Teste que si un produit est créé sans magasin spécifié,
    le produit n'est pas associé à un magasin (store = null).
    """
    client = APIClient()

    # Création d’un utilisateur
    user = User.objects.create_user(username="pierre", password="motdepasse")
    client.force_authenticate(user=user)

    # Création d’un produit sans store
    data = {
        "name": "Produit test",
        "description": "Description test",
        "price": "15.00",
        "available": True
    }

    # Envoi de la requête pour créer le produit
    response = client.post("/api/products/", data, format='json')

    # Vérifications
    assert response.status_code == 201  # Vérifier que la création a réussi
    product_id = response.data['id']
    product = Product.objects.get(id=product_id)

    # Vérifier que le produit n'a pas de store
    assert product.store is None
    # Vérifier que l'utilisateur est bien l'owner du produit
    assert product.owner == user


@pytest.mark.django_db
def test_product_associated_with_user_store():
    """
    Teste que si un produit est créé avec un store spécifié,
    il est associé à ce store et à son propriétaire.
    """
    client = APIClient()

    # Création d’un utilisateur
    user = User.objects.create_user(username="paul", password="motdepasse")
    client.force_authenticate(user=user)

    # Création d’un store privé pour l'utilisateur
    my_store = Store.objects.create(name="BoutiquePaul", owner=user)

    # Données du produit avec store
    data = {
        "name": "Produit Boutique",
        "description": "Test avec store",
        "price": "20.00",
        "store": my_store.id,  # Associer le produit à ce store
        "available": True
    }

    # Envoi de la requête pour créer le produit
    response = client.post("/api/products/", data, format='json')

    # Vérifications
    assert response.status_code == 201  # Vérifier que la création a réussi
    product_id = response.data['id']
    product = Product.objects.get(id=product_id)

    # Vérifier que le produit est associé au store de l'utilisateur
    assert product.store == my_store
    # Vérifier que l'utilisateur est bien l'owner du produit
    assert product.owner == user