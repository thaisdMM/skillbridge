"""
Tests for BaseUserManager and BaseUser model behavior.

Covers:
- BaseUserManager: create_user and create_superuser methods.
- BaseUser.clean(): invariants (superuser_without_staff, invalid_staff_privileges).
- BaseUser.has_perm() and has_module_perms(): permission gate behavior.

Uses two concrete models since BaseUser is abstract:
- Freelancer: the most complete concrete model (has is_available field), used for non-staff and non-superuser cases.
- StaffUser: used for superuser and staff behaviors, as it is the only concrete model that legitimately holds those privileges.
"""

import pytest
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError

from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser


@pytest.mark.django_db
def test_create_user_saves_to_database(valid_user_data: dict[str, str]) -> None:
    """Valid user data is persisted and receives a database ID."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.id is not None


@pytest.mark.django_db
def test_create_user_stores_correct_email(valid_user_data: dict[str, str]) -> None:
    """Email provided at creation is stored exactly as given."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.email == valid_user_data["email"]


@pytest.mark.django_db
def test_create_user_stores_correct_name(valid_user_data: dict[str, str]) -> None:
    """Name provided at creation is stored correctly."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.name == valid_user_data["name"]


@pytest.mark.django_db
def test_create_user_hashes_password(valid_user_data: dict[str, str]) -> None:
    """Password is hashed and never stored as plain text."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.password != valid_user_data["password"]
    assert check_password(valid_user_data["password"], user.password)


@pytest.mark.django_db
def test_create_user_default_flags(valid_user_data: dict[str, str]) -> None:
    """New user is active by default and has no staff or superuser privileges."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.is_active is True
    assert user.is_staff is False
    assert user.is_superuser is False


@pytest.mark.django_db
def test_create_user_without_password_has_no_usable_password(
    valid_user_data: dict[str, str],
) -> None:
    """User created without a password receives an unusable password."""
    user = Freelancer.objects.create_user(
        email=valid_user_data["email"],
        name=valid_user_data["name"],
    )

    assert user.id is not None
    assert not user.has_usable_password()


@pytest.mark.django_db
def test_create_user_normalizes_email(valid_user_data: dict[str, str]) -> None:
    """Uppercase letters in email domain are normalized to lowercase."""
    user = Freelancer.objects.create_user(
        **{**valid_user_data, "email": "TestUser@EXAMPLE.COM"}
    )

    assert user.email == "TestUser@example.com"


@pytest.mark.django_db
def test_create_user_strips_name_whitespace(valid_user_data: dict[str, str]) -> None:
    """Leading and trailing whitespace is removed from name before saving."""
    user = Freelancer.objects.create_user(
        **{**valid_user_data, "name": "  Test User  "}
    )

    assert user.name == "Test User"


@pytest.mark.django_db
def test_create_user_accepts_extra_fields(valid_user_data: dict[str, str]) -> None:
    """Freelancer-specific field is_available is accepted and saved correctly."""
    user = Freelancer.objects.create_user(**{**valid_user_data, "is_available": False})

    assert user.is_available is False


@pytest.mark.django_db
@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "invalidemail.com",
        "invalid@emailcom",
        "invalid@email..com",
        "@invalid.com",
        "invalid@email.c",
        "invalid@email.com.b",
        "user@",
        "user @email.com",
        "user@email .com",
        "user@.com",
    ],
)
def test_create_user_invalid_email_raises_validation_error(
    valid_user_data: dict[str, str],
    email: str,
) -> None:
    """Invalid email formats are rejected with a ValidationError."""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "email": email})


@pytest.mark.django_db
@pytest.mark.parametrize(
    "name",
    [
        "",
        "  ",
    ],
)
def test_create_user_name_empty_raises_validation_error(
    valid_user_data: dict[str, str],
    name: str,
) -> None:
    """Empty or whitespace-only name raises empty_name ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "name": name})

    assert exc_info.value.code == "empty_name"


@pytest.mark.django_db
def test_create_user_name_too_short_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """Name shorter than 2 characters raises name_too_short ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "name": "A"})

    assert exc_info.value.code == "name_too_short"


@pytest.mark.django_db
def test_create_user_name_too_long_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """Name exceeding 50 characters raises name_too_long ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "name": "A" * 51})

    assert exc_info.value.code == "name_too_long"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "password",
    [
        "   ",
        "Ab12!@",
    ],
)
def test_create_user_password_too_short_raises_validation_error(
    valid_user_data: dict[str, str],
    password: str,
) -> None:
    """Password shorter than 8 characters raises password_too_short ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": password})

    assert exc_info.value.code == "password_too_short"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "password",
    [
        "  Abc123!@  ",
        "Abc 123!@",
    ],
)
def test_create_user_password_contains_whitespace_raises_validation_error(
    valid_user_data: dict[str, str],
    password: str,
) -> None:
    """Password containing any whitespace raises password_contains_whitespace ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": password})

    assert exc_info.value.code == "password_contains_whitespace"


@pytest.mark.django_db
def test_create_user_password_only_digits_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """All-digit password raises password_only_digits ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": "123456789"})

    assert exc_info.value.code == "password_only_digits"


@pytest.mark.django_db
def test_create_user_password_missing_lowercase_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """Password with no lowercase letter raises password_missing_lowercase ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": "EFGH@!KKK"})

    assert exc_info.value.code == "password_missing_lowercase"


@pytest.mark.django_db
def test_create_user_password_missing_uppercase_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """Password with no uppercase letter raises password_missing_uppercase ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": "abcdef_.2"})

    assert exc_info.value.code == "password_missing_uppercase"


@pytest.mark.django_db
def test_create_user_password_no_special_char_raises_validation_error(
    valid_user_data: dict[str, str],
) -> None:
    """Password without a special character raises password_no_special_char ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        Freelancer.objects.create_user(**{**valid_user_data, "password": "abcDEF12"})

    assert exc_info.value.code == "password_no_special_char"


@pytest.mark.django_db
def test_create_superuser_saves_to_database(valid_user_data: dict[str, str]) -> None:
    """Valid superuser data is persisted and receives a database ID."""
    superuser = StaffUser.objects.create_superuser(**valid_user_data)

    assert superuser.id is not None


@pytest.mark.django_db
def test_create_superuser_has_correct_admin_flags(
    valid_user_data: dict[str, str],
) -> None:
    """Superuser is created with is_staff, is_superuser, and is_active set to True."""
    superuser = StaffUser.objects.create_superuser(**valid_user_data)

    assert superuser.is_staff is True
    assert superuser.is_superuser is True
    assert superuser.is_active is True


@pytest.mark.django_db
def test_create_superuser_hashes_password(valid_user_data: dict[str, str]) -> None:
    """Superuser password is hashed and never stored as plain text."""
    superuser = StaffUser.objects.create_superuser(**valid_user_data)

    assert superuser.password != valid_user_data["password"]
    assert check_password(valid_user_data["password"], superuser.password)


@pytest.mark.django_db
def test_create_super_user_with_is_staff_false_raises_value_error(
    valid_user_data: dict[str, str],
) -> None:
    """Superuser creation is rejected with ValueError when is_staff is not True."""
    with pytest.raises(ValueError, match="is_staff=True"):
        StaffUser.objects.create_superuser(**{**valid_user_data, "is_staff": False})


@pytest.mark.django_db
def test_create_super_user_with_is_superuser_false_raises_value_error(
    valid_user_data: dict[str, str],
) -> None:
    """Superuser creation is rejected with ValueError when is_superuser is not True."""
    with pytest.raises(ValueError, match="is_superuser=True"):
        StaffUser.objects.create_superuser(**{**valid_user_data, "is_superuser": False})


@pytest.mark.django_db
def test_clean_method_raises_validation_error_for_superuser_without_staff_status(
    valid_user_data: dict[str, str],
) -> None:
    """A superuser without staff status is rejected by full_clean() with code superuser_without_staff."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_superuser": True,
            "is_staff": False,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        user.full_clean()

    assert "is_staff" in exc_info.value.error_dict
    assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"


@pytest.mark.django_db
def test_clean_method_passes_for_valid_superuser(
    valid_user_data: dict[str, str],
) -> None:
    """Superuser with both is_superuser and is_staff set to True passes full_clean()."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_superuser": True,
            "is_staff": True,
        }
    )
    user.full_clean()


@pytest.mark.django_db
@pytest.mark.parametrize("privilege_field", ["is_staff", "is_superuser"])
def test_clean_method_raises_validation_error_for_non_staff_with_privileges(
    valid_user_data: dict[str, str],
    privilege_field: str,
) -> None:
    """A non-staff model assigned staff or superuser privileges is rejected with code invalid_staff_privileges."""
    user = Freelancer(
        **{
            **valid_user_data,
            privilege_field: True,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        user.full_clean()

    assert "is_staff" in exc_info.value.error_dict
    assert exc_info.value.error_dict["is_staff"][0].code == "invalid_staff_privileges"


def test_has_perm_returns_false_for_inactive_superuser(
    valid_user_data: dict[str, str],
) -> None:
    """A deactivated superuser is denied permissions despite is_superuser being True."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_superuser": True,
            "is_staff": True,
            "is_active": False,
        }
    )

    assert user.has_perm("any.perm") is False


def test_has_perm_returns_true_for_active_superuser(
    valid_user_data: dict[str, str],
) -> None:
    """An active superuser is granted permissions."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_superuser": True,
            "is_staff": True,
            "is_active": True,
        }
    )

    assert user.has_perm("any.perm") is True


def test_has_perm_returns_false_for_non_superuser(
    valid_user_data: dict[str, str],
) -> None:
    """An active non-superuser user is denied permissions."""
    user = Freelancer(
        **{
            **valid_user_data,
            "is_superuser": False,
            "is_active": True,
        }
    )

    assert user.has_perm("any.perm") is False


def test_has_module_perms_returns_true_for_active_staff_user(
    valid_user_data: dict[str, str],
) -> None:
    """An active staff user is granted admin module access."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_staff": True,
            "is_active": True,
        }
    )

    assert user.has_module_perms("any_app") is True


def test_has_module_perms_returns_false_for_inactive_staff_user(
    valid_user_data: dict[str, str],
) -> None:
    """A deactivated staff account loses admin module access despite is_staff being True."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_staff": True,
            "is_active": False,
        }
    )

    assert user.has_module_perms("any_app") is False


def test_has_module_perms_returns_false_for_non_staff_user(
    valid_user_data: dict[str, str],
) -> None:
    """An active non-staff user is denied admin module access."""
    user = Freelancer(
        **{
            **valid_user_data,
            "is_staff": False,
            "is_active": True,
        }
    )

    assert user.has_module_perms("any_app") is False
