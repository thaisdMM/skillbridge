"""
Tests for Client concrete model.

Client inherits all authentications and identifications
functionality from BaseUser, wich has its own tests.
"""

import pytest
from django.db.utils import IntegrityError

from accounts.models.client import Client


@pytest.mark.django_db
def test_client_user_type_returns_client(client_user):
    """Test that user_type @property returns 'client' for Client instance."""
    client = client_user

    assert client.user_type == "client"


@pytest.mark.django_db
def test_client_str_representation(client_user):
    """Test that __str__ returns user_type, name and email."""

    assert str(client_user) == "Client: Test User (testuser@example.com)"


@pytest.mark.django_db
def test_client_email_is_unique(client_user, valid_client_data):
    """Test that the database raises IntegrityError: when the same email is used twice."""
    client = client_user

    with pytest.raises(IntegrityError):
        Client.objects.create_user(**valid_client_data)


@pytest.mark.django_db
def test_client_create_user_has_correct_flags(client_user):
    """Test that a regular Client has is_staff and is_superuser set to False, and is_active set to True."""

    assert client_user.is_staff is False
    assert client_user.is_superuser is False
    assert client_user.is_active is True
