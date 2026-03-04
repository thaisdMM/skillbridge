"""Tests for user input validators - name"""

import pytest
from django.core.exceptions import ValidationError
from accounts.validators import validate_user_name


def test_validate_user_name_with_valid_requirements():
    """Test user name with valid requirements"""
    name = "User Name"
    try:
        validate_user_name(name)
    except ValidationError:
        pytest.fail("Valid user name raise ValidationError")


def test_validate_user_name_with_valid_requirements_min_length():
    """Test user name with valid requirements at minimum length (2 chars)"""
    name = "Ab"
    try:
        validate_user_name(name)
    except ValidationError:
        pytest.fail("Valid user name with minimum length raise ValidationError")


def test_validate_user_name_with_error_stripped_whitespace():
    """Test user name invalid with only whitespace is stripped and raise validation error"""
    name = "    "
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name(name)
    assert exc_info.value.code == "empty_name"


def test_validate_user_name_with_error_empty():
    """Test user name with error: empty"""
    name = ""
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name(name)
    assert exc_info.value.code == "empty_name"


def test_validate_user_name_with_error_too_short():
    """Test user name with error: too short"""
    name = "x"
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name(name)
    assert exc_info.value.code == "name_too_short"


def test_validate_user_name_with_error_too_long():
    """Test user name with error: too long"""
    name = "x" * 51
    with pytest.raises(ValidationError) as exc_info:
        validate_user_name(name)
    assert exc_info.value.code == "name_too_long"
