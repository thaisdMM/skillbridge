"""Tests for user input validators - name"""

import pytest
from django.core.exceptions import ValidationError

from accounts.validators import validate_user_name


def test_validate_user_name_with_valid_requirements() -> None:
    """Test user name with valid requirements"""
    validate_user_name("User Name")


def test_validate_user_name_with_valid_requirements_min_length() -> None:
    """Test user name with valid requirements at minimum length (2 chars)"""
    validate_user_name("Ab")


def test_validate_user_name_with_error_stripped_whitespace() -> None:
    """Test user name invalid with only whitespace is stripped and raise validation error"""
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name("    ")

    assert exc_info.value.code == "empty_name"


def test_validate_user_name_with_error_empty() -> None:
    """Test user name with error: empty"""
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name("")

    assert exc_info.value.code == "empty_name"


def test_validate_user_name_with_error_too_short() -> None:
    """Test user name with error: too short"""
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name("x")

    assert exc_info.value.code == "name_too_short"


def test_validate_user_name_with_error_too_long() -> None:
    """Test user name with error: too long"""
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name("x" * 51)

    assert exc_info.value.code == "name_too_long"
