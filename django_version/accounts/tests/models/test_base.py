"""
Tests for BaseUserManager (create_user and create_superuser methods).

Uses Freelancer as the concrete model since BaseUser is abstract.
Freelancer is the most complete concrete model (has is_available field)
"""

import pytest
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError

from accounts.models.freelancer import Freelancer

# TESTS: create_user() - VALID SCENARIOS


@pytest.mark.django_db
def test_create_user_saves_to_database(valid_user_data):
    """Valid user data is persisted and receives a database ID."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.id is not None


@pytest.mark.django_db
def test_create_user_stores_correct_email(valid_user_data):
    """Email provided at creation is stored exactly as given."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.email == valid_user_data["email"]


@pytest.mark.django_db
def test_create_user_stores_correct_name(valid_user_data):
    """Name provided at creation is stored correctly."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.name == valid_user_data["name"]


@pytest.mark.django_db
def test_create_user_hashes_password(valid_user_data):
    """Password is hashed and never stored as plain text."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.password != valid_user_data["password"]
    assert check_password(valid_user_data["password"], user.password)


@pytest.mark.django_db
def test_create_user_default_flags(valid_user_data):
    """New user is active by default and has no staff or superuser privileges."""
    user = Freelancer.objects.create_user(**valid_user_data)

    assert user.is_active is True
    assert user.is_staff is False
    assert user.is_superuser is False


@pytest.mark.django_db
def test_create_user_without_password_has_no_usable_password(valid_user_data):
    """Test create user without password set unusable password in database"""
    user = Freelancer.objects.create_user(
        email=valid_user_data["email"],
        name=valid_user_data["name"],
    )

    assert user.id is not None
    assert not user.has_usable_password()


@pytest.mark.django_db
def test_create_user_normalizes_email(valid_user_data):
    """Uppercase letters in email domain are normalized to lowercase."""
    user = Freelancer.objects.create_user(
        **{**valid_user_data, "email": "TestUser@EXAMPLE.COM"}
    )

    assert user.email == "TestUser@example.com"


@pytest.mark.django_db
def test_create_user_strips_name_whitespace(valid_user_data):
    """Leading and trailing whitespace is removed from name before saving."""
    user = Freelancer.objects.create_user(
        **{**valid_user_data, "name": "  Test User  "}
    )

    assert user.name == "Test User"


@pytest.mark.django_db
def test_create_user_accepts_extra_fields(valid_user_data):
    """Freelancer-specific field is_available is accepted and saved correctly."""
    user = Freelancer.objects.create_user(**{**valid_user_data, "is_available": False})

    assert user.is_available is False


# TEST: create_user() - INVALID SCENARIOS


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
def test_create_user_invalid_email_raises_validation_error(valid_user_data, email):
    """Test with list of parameterized invalid emails raises ValidationError"""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "email": email})


@pytest.mark.django_db
@pytest.mark.parametrize(
    "name",
    [
        "",
        "  ",
        "A",
        "A" * 51,
    ],
)
def test_create_user_invalid_name_raises_validation_error(valid_user_data, name):
    """Test with list of parameterized invalid names raises ValidationError"""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "name": name})


@pytest.mark.django_db
@pytest.mark.parametrize(
    "password",
    [
        "Ab12!@",
        "Abc 123!@",
        "123456789",
        "EFGH@!KKK",
        "abcdef_.2",
        "abcDEF12",
    ],
)
def test_create_user_invalid_password_raises_validation_error(
    valid_user_data, password
):
    """Test with list of parameterized invalid passwords raises ValidationError"""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "password": password})


# TEST: create_superuser() - VALID SCENARIOS


@pytest.mark.django_db
def test_create_superuser_saves_to_database(valid_user_data):
    """Valid superuser data is persisted and receives a database ID."""
    superuser = Freelancer.objects.create_superuser(**valid_user_data)

    assert superuser.id is not None


@pytest.mark.django_db
def test_create_superuser_has_correct_admin_flags(valid_user_data):
    """Superuser is created with is_staff, is_superuser, and is_active set to True."""
    superuser = Freelancer.objects.create_superuser(**valid_user_data)

    assert superuser.is_staff is True
    assert superuser.is_superuser is True
    assert superuser.is_active is True


@pytest.mark.django_db
def test_create_superuser_hashes_password(valid_user_data):
    """Test create superuser hashes password"""
    superuser = Freelancer.objects.create_superuser(**valid_user_data)

    assert superuser.password != valid_user_data["password"]
    assert check_password(valid_user_data["password"], superuser.password)


# TEST: create_superuser() - INVALID SCENARIOS


@pytest.mark.django_db
def test_create_super_user_with_is_staff_false_raises_value_error(valid_user_data):
    """Test create superuser with is_staff False failed and raises ValueError"""
    with pytest.raises(ValueError, match="Superuser must have is_staff=True"):
        Freelancer.objects.create_superuser(**{**valid_user_data, "is_staff": False})


@pytest.mark.django_db
def test_create_super_user_with_is_superuser_false_raises_value_error(valid_user_data):
    """Test create superuser with is_superuser False failed and raises ValueError"""
    with pytest.raises(ValueError, match="Superuser must have is_superuser=True"):
        Freelancer.objects.create_superuser(
            **{**valid_user_data, "is_superuser": False}
        )
