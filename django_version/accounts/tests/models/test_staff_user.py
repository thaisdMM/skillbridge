"""
Tests for StaffUser model.

StaffUser is the project's AUTH_USER_MODEL — the model Django uses
for authentication. It inherits all authentication functionality from
BaseUser (tested in test_base.py) and overrides is_staff default to True.
"""

import pytest

from accounts.models.staff_user import StaffUser


@pytest.mark.django_db
def test_create_staff_user_has_is_staff_true_by_default(
    valid_user_data: dict[str, str],
) -> None:
    """StaffUser created without is_staff has is_staff=True from the field override."""
    user = StaffUser.objects.create_user(**valid_user_data)

    assert user.is_staff is True
