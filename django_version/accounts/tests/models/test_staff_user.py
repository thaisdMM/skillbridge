"""
Tests for StaffUser model.

StaffUser is the project's AUTH_USER_MODEL — the model Django uses
for authentication. It inherits all authentication functionality from
BaseUser (tested in test_base.py) and overrides is_staff default to True.
"""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from accounts.models.staff_user import StaffUser


@pytest.mark.django_db
def test_create_staff_user_has_is_staff_true_by_default(
    valid_user_data: dict[str, str],
) -> None:
    """StaffUser created without is_staff has is_staff=True from the field override."""
    user = StaffUser.objects.create_user(**valid_user_data)

    assert user.is_staff is True


@pytest.mark.django_db
def test_clean_raises_when_active_and_not_staff(
    valid_user_data: dict[str, str],
) -> None:
    """An active StaffUser without staff status raises a staffuser_active_without_staff error."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_active": True,
            "is_staff": False,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        user.full_clean()

    assert "is_staff" in exc_info.value.error_dict
    assert (
        exc_info.value.error_dict["is_staff"][0].code
        == "staffuser_active_without_staff"
    )


@pytest.mark.django_db
def test_create_user_rejects_active_staff_user_without_staff_status(
    valid_user_data: dict[str, str],
) -> None:
    """create_user() invokes full_clean(), rejecting an active non-staff StaffUser with code staffuser_active_without_staff."""
    with pytest.raises(ValidationError) as exc_info:
        StaffUser.objects.create_user(
            **valid_user_data,
            is_active=True,
            is_staff=False,
        )

    assert "is_staff" in exc_info.value.error_dict
    assert (
        exc_info.value.error_dict["is_staff"][0].code
        == "staffuser_active_without_staff"
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("is_active", "is_staff"),
    [
        (True, True),
        (False, True),
        (False, False),
    ],
)
def test_clean_does_not_raise_for_valid_active_staff_states(
    valid_user_data: dict[str, str],
    is_active: bool,
    is_staff: bool,
) -> None:
    """The three allowed active/staff combinations pass full_clean() without error."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_active": is_active,
            "is_staff": is_staff,
        }
    )

    user.full_clean()


@pytest.mark.django_db
def test_constraint_raises_integrity_error_on_update_bypassing_clean(
    valid_user_data: dict[str, str],
) -> None:
    """A direct .update() activating a non-staff StaffUser violates the database constraint."""
    user = StaffUser.objects.create_user(
        **valid_user_data,
        is_active=False,
        is_staff=False,
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            StaffUser.objects.filter(pk=user.pk).update(is_active=True)


@pytest.mark.django_db
def test_constraint_allows_inactive_non_staff_via_direct_update(
    valid_user_data: dict[str, str],
) -> None:
    """A direct ORM update to is_active=False and is_staff=False succeeds and persists."""
    user = StaffUser.objects.create_user(**valid_user_data)

    StaffUser.objects.filter(pk=user.pk).update(is_active=False, is_staff=False)

    user.refresh_from_db()
    assert user.is_active is False
    assert user.is_staff is False


def test_staff_user_user_type_returns_staffuser(
    valid_user_data: dict[str, str],
) -> None:
    """user_type property returns 'staffuser' for StaffUser instances."""
    user = StaffUser(**valid_user_data)
    assert user.user_type == "staffuser"
