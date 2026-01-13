import pytest
from src.utils.validators import validate_email


def test_validate_email_valid_simple():
    """Test simple valid email format."""

    email = "user@example.com"
    result = validate_email(email)
    assert result is True


def test_validate_email_valid_with_compound_domain():
    """Test a valid email format with a compound domain (e.g., .com.br)"""

    email = "user@example.com.br"
    result = validate_email(email)
    assert result is True


def test_validate_email_valid_with_subdomain():
    """Test a valid email format with a subdomain"""

    email = "e@email.subdomain.com"
    result = validate_email(email)
    assert result is True


def test_validate_email_valid_with_numbers_in_username():
    """Test a valid email format with numbers in username"""

    email = "user51@email.com"
    result = validate_email(email)
    assert result is True


def test_validate_email_valid_with_special_characters():
    """Test a valid email format with special characters (+, _, %, -)"""

    email = "user+35@email.com.us"
    result = validate_email(email)
    assert result is True


def test_validate_email_invalid_missing_at_symbol():
    """Test an invalid email format without @ symbol"""

    email = "userexample.com"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_missing_dot_symbol_after_at_symbol():
    """Test an invalid email format without dot symbol after @ symbol"""

    email = "user@examplecom"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_format_with_double_dots():
    """Test an invalid email format with consecutive dots in domain"""

    email = "user@domain..com"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_format_with_spaces():
    """Test an invalid email format with spaces"""

    email = "user @example.com"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_format_with_single_letter_tld():
    """Test an invalid email format with single-letter TLD"""

    email = "user@example.c"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_missing_domain():
    """Test an invalid email format without domain between @ and dot"""

    email = "user@.com"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_format_without_username():
    """Test an invalid email format without username before @ symbol"""

    email = "@domain.com"
    result = validate_email(email)
    assert result is False


def test_validate_email_invalid_format_compound_domain_short_tld():
    """Test an invalid email format for compound domain with TLD less than two characters"""

    email = "user@email.com.r"
    result = validate_email(email)
    assert result is False
