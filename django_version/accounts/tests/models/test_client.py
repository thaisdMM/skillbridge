"""
Tests for Client concrete model.

Client inherits all authentications and identifications
functionality from BaseUser, which has its own tests.
"""

import pytest
from django.core.exceptions import ValidationError

from accounts.models.client import Client


@pytest.mark.django_db
def test_client_user_type_returns_client(client_user: Client) -> None:
    """user_type property returns 'client' for a Client instance."""
    assert client_user.user_type == "client"


@pytest.mark.django_db
def test_client_str_representation(client_user: Client) -> None:
    """__str__ returns a non-PII string containing the class name and id."""
    assert str(client_user) == f"Client (id={client_user.id})"


@pytest.mark.django_db
def test_client_repr_representation(client_user: Client) -> None:
    """__repr__ returns a non-PII string containing the class name and id."""
    assert repr(client_user) == f"Client (id={client_user.id})"


@pytest.mark.django_db
def test_client_email_is_unique(
    client_user: Client, valid_client_data: dict[str, str]
) -> None:
    """Duplicate email is rejected by create_user() with a unique ValidationError before reaching the database."""
    with pytest.raises(ValidationError) as exc_info:
        Client.objects.create_user(**valid_client_data)

    assert "email" in exc_info.value.error_dict
    assert exc_info.value.error_dict["email"][0].code == "unique"


@pytest.mark.django_db
def test_client_create_user_has_correct_flags(client_user: Client) -> None:
    """A newly created Client has no staff privileges and is active by default."""
    assert client_user.is_staff is False
    assert client_user.is_superuser is False
    assert client_user.is_active is True


@pytest.mark.django_db
def test_client_created_at_is_set_on_creation(client_user: Client) -> None:
    """created_at is populated when the instance is first saved."""
    assert client_user.created_at is not None
