"""
Tests for user input validators.
Adapted from OOP version to Django validation system.
"""

import pytest
from django.core.exceptions import ValidationError
from accounts.validators import validate_email


def test_validate_email_valid_simple():
    """Test simple valid email format."""

    email = "user@example.com"

    try:
        validate_email(email)
    except ValidationError:
        pytest.fail("Valid email raised ValidationError")


def test_validate_email_valid_with_compound_domain():
    """Test a valid email format with a compound domain (e.g., .com.br)"""

    email = "user@example.com.br"
    try:
        validate_email(email)
    except ValidationError:
        pytest.fail("Valid email with compound domain raised ValidationError ")


def test_validate_email_valid_with_subdomain():
    """Test a valid email format with a subdomain"""

    email = "e@email.subdomain.com"
    try:
        validate_email(email)
    except ValidationError:
        pytest.fail("Valid email with subdomain raised ValidationError ")


def test_validate_email_valid_with_numbers_in_username():
    """Test a valid email format with numbers in username"""

    email = "user51@email.com"
    try:
        validate_email(email)
    except ValidationError:
        pytest.fail("Valid email with numbers in username raised ValidationError ")


def test_validate_email_valid_with_special_characters():
    """Test a valid email format with special characters (+, _, %, -)"""

    email = "user+35@email.com.us"
    try:
        validate_email(email)
    except ValidationError:
        pytest.fail("Valid email with special characters raised ValidationError ")


def test_validate_email_invalid_empty():
    """Test an invalid email - empty email"""
    email = ""

    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "empty_email"


def test_validate_email_invalid_empty_stripped_whitespace():
    """Test an invalid email - empty with whitespace"""
    email = "    "

    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "empty_email"


def test_validate_email_invalid_missing_at_symbol():
    """Test an invalid email format without @ symbol"""

    email = "userexample.com"

    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_missing_dot_symbol_after_at_symbol():
    """Test an invalid email format without dot symbol after @ symbol"""

    email = "user@examplecom"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_double_dots():
    """Test an invalid email format with consecutive dots in domain"""

    email = "user@domain..com"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_spaces():
    """Test an invalid email format with spaces"""

    email = "user @example.com"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_with_single_letter_tld():
    """Test an invalid email format with single-letter TLD"""

    email = "user@example.c"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_missing_domain():
    """Test an invalid email format without domain between @ and dot"""

    email = "user@.com"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_without_username():
    """Test an invalid email format without username before @ symbol"""

    email = "@domain.com"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"


def test_validate_email_invalid_format_compound_domain_short_tld():
    """Test an invalid email format for compound domain with TLD less than two characters"""

    email = "user@email.com.r"
    with pytest.raises(ValidationError) as exc_info:
        validate_email(email)

    assert exc_info.value.code == "invalid_email"
