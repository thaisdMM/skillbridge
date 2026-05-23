"""
Tests for Freelancer model.

Freelancer inherits all authentication and identification
functionality from BaseUser, which has its own tests.
"""

import pytest
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from accounts.models.freelancer import Freelancer


@pytest.mark.django_db
def test_freelancer_user_type_returns_freelancer(freelancer_user):
    """Test that user_type property returns 'freelancer' for Freelancer instances."""

    assert freelancer_user.user_type == "freelancer"


@pytest.mark.django_db
def test_freelancer_is_available_default_is_true(freelancer_user):
    """Test that is_available field defaults to True."""

    assert freelancer_user.is_available is True


@pytest.mark.django_db
def test_freelancer_is_available_can_be_set_false(freelancer_user):
    """Test that is_available can be updated to False and persisted in the database."""

    freelancer_user.is_available = False
    freelancer_user.save()
    freelancer_user.refresh_from_db()
    assert freelancer_user.is_available is False


@pytest.mark.django_db
def test_freelancer_str_representation(freelancer_user):
    """Test that __str__ returns user type, name and email."""

    assert str(freelancer_user) == "Freelancer: Test User (testuser@example.com)"


@pytest.mark.django_db
def test_freelancer_email_is_unique(freelancer_user, valid_freelancer_data):
    """Test that the database raises IntegrityError when the same email is used twice."""
    with pytest.raises(IntegrityError):
        Freelancer.objects.create_user(**valid_freelancer_data)


@pytest.mark.django_db
def test_freelancer_create_user_has_correct_default_flags(freelancer_user):
    """Test that a regular Freelancer has is_staff and is_superuser set to False, and is_active set to True."""

    assert freelancer_user.is_staff is False
    assert freelancer_user.is_superuser is False
    assert freelancer_user.is_active is True


@pytest.mark.django_db
def test_freelancer_clean_raises_if_inactive_and_available(valid_freelancer_data):
    """Test that full_clean() raises ValidationError when freelancer is inactive and available."""
    freelancer = Freelancer(
        **{
            **valid_freelancer_data,
            "is_active": False,
            "is_available": True,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        freelancer.full_clean()

    assert exc_info.value.error_dict["is_available"][0].code == "freelancer_inactive_available"


@pytest.mark.django_db
def test_freelancer_clean_passes_if_inactive_and_unavailable(valid_freelancer_data):
    """Test that full_clean() passes when freelancer is inactive and unavailable."""
    freelancer = Freelancer(
        **{
            **valid_freelancer_data,
            "is_active": False,
            "is_available": False,
        }
    )
    freelancer.full_clean()
