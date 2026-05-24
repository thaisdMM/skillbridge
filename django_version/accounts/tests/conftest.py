"""Shared fixtures for accounts app tests."""

import pytest

from accounts.models.freelancer import Freelancer
from accounts.models.client import Client


@pytest.fixture
def valid_user_data() -> dict[str, str]:
    """
    Valid data to create a generic user.

    Returns dict (not object) for flexibility in test creation.
    Allows unpacking: User.objects.create(**valid_user_data)
    """
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }


@pytest.fixture
def valid_freelancer_data(valid_user_data: dict[str, str]) -> dict[str, str | bool]:
    """
    Valid data to create a Freelancer user.

    Inherits from valid_user_data and adds Freelancer-specific fields.
    """
    return {
        **valid_user_data,
        "is_available": True,
    }


@pytest.fixture
def valid_client_data(valid_user_data: dict[str, str]) -> dict[str, str]:
    """
    Valid data to create a Client user.

    Client has no extra fields, so returns valid_user_data.
    """
    return valid_user_data


@pytest.fixture
def freelancer_user(db, valid_freelancer_data: dict[str, str | bool]) -> Freelancer:
    """Create and return a Freelancer instance saved in the test database."""

    return Freelancer.objects.create_user(**valid_freelancer_data)


@pytest.fixture
def client_user(db, valid_client_data: dict[str, str]) -> Client:
    """Create and return a Client instance saved in the test database."""

    return Client.objects.create_user(**valid_client_data)
