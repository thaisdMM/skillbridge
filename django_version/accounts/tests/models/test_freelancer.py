"""
Tests for Freelancer model.

Freelancer inherits all authentication and identification
functionality from BaseUser, which has its own tests.
"""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from accounts.models.freelancer import Freelancer


@pytest.mark.django_db
def test_freelancer_user_type_returns_freelancer(
    freelancer_user: Freelancer,
) -> None:
    """user_type property returns 'freelancer' for Freelancer instances."""
    assert freelancer_user.user_type == "freelancer"


@pytest.mark.django_db
def test_freelancer_is_available_default_is_true(
    valid_user_data: dict[str, str],
) -> None:
    """is_available defaults to True when no value is supplied at creation."""
    freelancer = Freelancer.objects.create_user(**valid_user_data)
    assert freelancer.is_available is True


@pytest.mark.django_db
def test_freelancer_is_available_can_be_set_false(
    freelancer_user: Freelancer,
) -> None:
    """is_available can be updated to False and the change is persisted in the database."""
    freelancer_user.is_available = False
    freelancer_user.save()
    freelancer_user.refresh_from_db()
    assert freelancer_user.is_available is False


@pytest.mark.django_db
def test_freelancer_str_representation(freelancer_user: Freelancer) -> None:
    """__str__ returns a non-PII string containing the class name and id."""
    assert str(freelancer_user) == f"Freelancer (id={freelancer_user.id})"


@pytest.mark.django_db
def test_freelancer_repr_representation(freelancer_user: Freelancer) -> None:
    """__repr__ includes class name, id, and availability status."""
    assert repr(freelancer_user) == (
        f"Freelancer (id={freelancer_user.id}, "
        f"is_available={freelancer_user.is_available})"
    )


@pytest.mark.django_db
def test_freelancer_email_is_unique(
    freelancer_user: Freelancer,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Duplicate email is rejected by create_user() with a unique ValidationError before reaching the database."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**valid_freelancer_data)

    assert "email" in exc_info.value.error_dict
    assert exc_info.value.error_dict["email"][0].code == "unique"


@pytest.mark.django_db
def test_create_user_rejects_inactive_and_available_freelancer(
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """create_user() invokes full_clean(), rejecting an inactive-but-available freelancer with code freelancer_inactive_available."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(
            **{**valid_freelancer_data, "is_active": False, "is_available": True}
        )

    assert "is_available" in exc_info.value.error_dict
    assert (
        exc_info.value.error_dict["is_available"][0].code
        == "freelancer_inactive_available"
    )


@pytest.mark.django_db
def test_freelancer_clean_raises_if_inactive_and_available(
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """An inactive freelancer marked as available is rejected by full_clean() with code freelancer_inactive_available."""
    freelancer = Freelancer(
        **{
            **valid_freelancer_data,
            "is_active": False,
            "is_available": True,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        freelancer.full_clean()

    assert "is_available" in exc_info.value.error_dict
    assert (
        exc_info.value.error_dict["is_available"][0].code
        == "freelancer_inactive_available"
    )


@pytest.mark.django_db
def test_freelancer_clean_passes_if_inactive_and_unavailable(
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """An inactive freelancer marked as unavailable passes full_clean() without error."""
    freelancer = Freelancer(
        **{
            **valid_freelancer_data,
            "is_active": False,
            "is_available": False,
        }
    )
    freelancer.full_clean()


@pytest.mark.django_db
def test_freelancer_created_at_is_set_on_creation(freelancer_user: Freelancer) -> None:
    """created_at is populated when the instance is first saved."""
    assert freelancer_user.created_at is not None


@pytest.mark.django_db
def test_check_constraint_rejects_inactive_and_available_via_direct_update(
    freelancer_user: Freelancer,
) -> None:
    """A direct ORM update to is_active=False and is_available=True raises IntegrityError."""
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Freelancer.objects.filter(pk=freelancer_user.pk).update(
                is_active=False, is_available=True
            )


@pytest.mark.django_db
def test_check_constraint_allows_inactive_and_unavailable_via_direct_update(
    freelancer_user: Freelancer,
) -> None:
    """A direct ORM update to is_active=False and is_available=False succeeds and persists."""
    Freelancer.objects.filter(pk=freelancer_user.pk).update(
        is_active=False, is_available=False
    )
    freelancer_user.refresh_from_db()
    assert freelancer_user.is_active is False
    assert freelancer_user.is_available is False
