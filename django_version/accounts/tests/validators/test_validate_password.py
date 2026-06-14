"""Tests for the validate_strong_password validator."""

import pytest
from django.core.exceptions import ValidationError

from accounts.validators import validate_strong_password


def test_validate_strong_password_with_all_requirements_valid() -> None:
    """Valid password passes without raising ValidationError."""
    validate_strong_password("Abc123!@")


@pytest.mark.parametrize(
    "password",
    [
        "  Abc123!@  ",
        "Abc 123!@",
    ],
)
def test_validate_strong_password_with_whitespace_raises_error(password: str) -> None:
    """Password containing any whitespace raises password_contains_whitespace ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password(password)

    assert exc_info.value.code == "password_contains_whitespace"


def test_validate_strong_password_with_error_length_too_short() -> None:
    """Password shorter than 8 characters raises password_too_short ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password("Ab123!@")

    assert exc_info.value.code == "password_too_short"


def test_validate_strong_password_with_error_only_number_digits() -> None:
    """Password with only digits raises password_only_digits ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password("123456789")

    assert exc_info.value.code == "password_only_digits"


def test_validate_strong_password_with_error_only_uppercase_letters() -> None:
    """Password with only uppercase letters raises password_all_uppercase ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password("EFGH@!KKK")

    assert exc_info.value.code == "password_all_uppercase"


def test_validate_strong_password_with_error_only_lowercase_letters() -> None:
    """Password with only lowercase letters raises password_all_lowercase ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password("abcdef_.2")

    assert exc_info.value.code == "password_all_lowercase"


def test_validate_strong_password_with_error_no_special_character() -> None:
    """Password without a special character raises password_no_special_char ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        validate_strong_password("abcDEF12")

    assert exc_info.value.code == "password_no_special_char"
