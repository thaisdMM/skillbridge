"""
Tests for user input validators - password.
Adapted from OOP version to Django validation system.
"""

import pytest
from django.core.exceptions import ValidationError
from accounts.validators import validate_strong_password


def test_validate_strong_password_with_all_requirements_valid():
    """Test password with all requirements is valid"""

    password = "Abc123!@"

    try:
        validate_strong_password(password)

    except ValidationError:
        pytest.fail("Valid password raised ValidationError")


def test_validate_strong_password_with_all_requirements_stripped_whitespace():
    """Test password with all requirements stripped withespace"""

    password = "  Abc123!@  "

    try:
        validate_strong_password(password)

    except ValidationError:
        pytest.fail("Valid password raised ValidationError")


def test_validate_strong_password_with_error_length_too_short():
    """Test password with error: password length less than 8"""

    password = "Ab123!@"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_too_short"


def test_validate_strong_password_with_error_space():
    """Test password with error: password with space"""

    password = "Abc 123!@"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_contains_whitespace"


def test_validate_strong_password_with_error_only_number_digits():
    """Test password with error: password with only number digits"""

    password = "123456789"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_only_digits"


def test_validate_strong_password_with_error_only_uppercase_letters():
    """Test password with error: password with only uppercase letters"""

    password = "EFGH@!KKK"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_all_uppercase"


def test_validate_strong_password_with_error_only_lowercase_letters():
    """Test password with error: password with only lowercase letters"""

    password = "abcdef_.2"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_all_lowercase"


def test_validate_strong_password_with_error_no_special_character():
    """Test password with error: password without special character"""

    password = "abcDEF12"

    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_no_special_char"
