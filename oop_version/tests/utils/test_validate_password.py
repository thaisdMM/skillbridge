"""
Tests for user input validate password.
"""

import pytest
from src.utils.validators import validate_password


def test_validate_password_valid_with_all_requirements():
    """Test password with all requirements is valid"""
    # Arrange
    password = "Abc123!@"

    # Act
    is_valid, message = validate_password(password)

    # Assert
    assert is_valid is True
    assert message == ""


def test_validate_password_with_error_length_too_short():
    """Test password with error: password length less than 8"""

    password = "Ab123!@"

    is_valid, message = validate_password(password)

    assert is_valid is False
    assert message == "Password must be at least 8 characters long."


def test_validate_password_with_error_only_number_digits():
    """Test password with error: password with only number digits"""

    password = "123456789"

    is_valid, message = validate_password(password)

    assert is_valid is False
    assert (
        message
        == "Password cannot contain only digits, it must include letters and special characters."
    )


def test_validate_password_with_error_only_alpha_characters():
    """Test password with error: password with only alpha characters"""

    password = "abcdEFGH"

    is_valid, message = validate_password(password)

    assert is_valid is False
    assert message == "Password must contain at least one special character."


def test_validate_password_with_error_only_uppercase_letters():
    """Test password with error: password with only uppercase letters"""

    password = "EFGH@!KKK"

    is_valid, message = validate_password(password)

    assert is_valid is False
    assert (
        message
        == "Password cannot be all uppercase, it must contain at least one lowercase letter."
    )


def test_validate_password_with_error_only_lowercase_letters():
    """Test password with error: password with only lowercase letters"""

    password = "abcdef_.2"

    is_valid, message = validate_password(password)

    assert is_valid is False
    assert (
        message
        == "Password cannot be all lowercase, it must contain at least one uppercase letter."
    )


# Test with customized error message
def test_validate_password_with_error_no_special_character():
    """Test password with error: password without special character"""

    password = "abcDEF12"
    expected_message = "Password must contain at least one special character."

    is_valid, message = validate_password(password)

    assert is_valid is False, f"Expected password '{password}' to be invalid."
    assert (
        message == expected_message
    ), f"Got: '{message}', Expected: {expected_message}"


# # example with error to se the result with customized error message
# def test_validate_password_with_error_no_special_character():
#     """Test password with error: password without special character"""
#     password = "abcDEF12"
#     expected_message = "MESSAGE WITH ERROR"

#     is_valid, message = validate_password(password)

#     assert is_valid is False, f"Expected password '{password}' to be invalid."
#     assert (
#         message == expected_message
#     ), f"Got: '{message}', Expected: {expected_message}"
