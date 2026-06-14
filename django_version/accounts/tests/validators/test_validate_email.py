"""
Tests for user input validators.
Adapted from OOP version to Django validation system.
"""

import pytest
from django.core.exceptions import ValidationError

from accounts.validators import validate_email


def test_validate_email_valid_simple() -> None:
    """Test simple valid email format."""
    validate_email("user@example.com")


def test_validate_email_valid_with_compound_domain() -> None:
    """Test a valid email format with a compound domain (e.g., .com.br)"""
    validate_email("user@example.com.br")


def test_validate_email_valid_with_subdomain() -> None:
    """Test a valid email format with a subdomain"""
    validate_email("e@email.subdomain.com")


def test_validate_email_valid_with_numbers_in_username() -> None:
    """Test a valid email format with numbers in username"""
    validate_email("user51@email.com")


def test_validate_email_valid_with_special_characters() -> None:
    """Test a valid email format with special characters (+, _, %, -)"""
    validate_email("user+35@email.com.us")


def test_validate_email_invalid_empty() -> None:
    """Test an invalid email - empty email"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("")

    assert exc_info.value.code == "empty_email"


def test_validate_email_invalid_empty_stripped_whitespace() -> None:
    """Test an invalid email - empty with whitespace"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("    ")

    assert exc_info.value.code == "empty_email"


def test_validate_email_invalid_missing_at_symbol() -> None:
    """Test an invalid email format without @ symbol"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("userexample.com")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_missing_dot_symbol_after_at_symbol() -> None:
    """Test an invalid email format without dot symbol after @ symbol"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user@examplecom")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_double_dots() -> None:
    """Test an invalid email format with consecutive dots in domain"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user@domain..com")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_spaces() -> None:
    """Test an invalid email format with spaces"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user @example.com")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_single_letter_tld() -> None:
    """Test an invalid email format with single-letter TLD"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user@example.c")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_missing_domain() -> None:
    """Test an invalid email format without domain between @ and dot"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user@.com")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_without_username() -> None:
    """Test an invalid email format without username before @ symbol"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("@domain.com")

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_compound_domain_short_tld() -> None:
    """Test an invalid email format for compound domain with TLD less than two characters"""
    with pytest.raises(ValidationError) as exc_info:
        validate_email("user@email.com.r")

    assert exc_info.value.code == "invalid_email"
