"""
Unit tests for User abstract base class.

Tests verify that User maintains its abstract nature and cannot be
instantiated directly, ensuring architectural integrity.
"""

import pytest
from datetime import datetime
from src.models.user import User


# Fixtures (reusable data)
@pytest.fixture
def valid_email():
    """Reusable valid email for tests"""
    return "test@domain.com"


@pytest.fixture
def invalid_email():
    """Reusable invalid email for tests"""
    return "user@domain..com"


@pytest.fixture
def valid_name():
    """Reusable valid name for tests"""
    return "Test User"


@pytest.fixture
def valid_password():
    """Reusable valid password for tests"""
    return "Secure_Abc123!@!"


@pytest.fixture
def invalid_password():
    """Reusable invalid password for tests"""
    return "invalid_password"


@pytest.fixture
def hashed_password():
    "Reusable Password already hashed for tests"
    from src.utils.security import hash_password

    return hash_password("Secure_Abc123!@!")


def test_user_cannot_be_instantiated_directly():
    """Test that User is abstract and cannot be created directly.

    This test ensures User remains abstract even if ABC or @abstractmethod
    is accidentally removed. It prevents architectural bugs where User
    could be instantiated directly instead of through subclasses.
    """
    with pytest.raises(TypeError) as exc_info:
        User(
            user_id=1,
            email="test@test.com",
            name="Test User",
            hashed_password="$argon2id$v=19$m=65536,t=3,p=4$hash",
            created_at=datetime.now(),
        )
    error_message = str(exc_info.value).lower()
    assert "abstract" in error_message or "can't instantiate" in error_message


def test_validate_creation_data_correct_data(
    valid_email: str, valid_name: str, valid_password: str
):
    """Test _validate_creation_data() with valid data"""

    result = User._validate_creation_data(valid_email, valid_name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is True
    assert message == ""


def test_validate_creation_data_with_invalid_email_returns_false(
    invalid_email: str, valid_name: str, valid_password: str
):
    """Test that _validate_creation_data() with invalid email returns False"""

    result = User._validate_creation_data(invalid_email, valid_name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message == "Invalid email"


def test_validate_creation_data_with_invalid_password_returns_false(
    valid_email: str, valid_name: str, invalid_password: str
):
    """Test that _validate_creation_data() with invalid password returns False"""

    result = User._validate_creation_data(valid_email, valid_name, invalid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message != ""


def test_validate_creation_data_with_empty_name_returns_false(
    valid_email: str, valid_password: str
):
    """Test that _validate_creation_data() with empty name returns False"""

    name = ""
    result = User._validate_creation_data(valid_email, name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message == "Name cannot be empty"


def test_validate_creation_data_with_whitespace_name_strip_correctly_returns_false(
    valid_email: str, valid_password: str
):
    """Test that _validate_creation_data() with whitespace name is correctly stripped and returns False"""

    name = "   "
    result = User._validate_creation_data(valid_email, name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message == "Name cannot be empty"


def test_validate_creation_data_with_too_short_name_returns_false(
    valid_email: str, valid_password: str
):
    """Test that _validate_creation_data() with name less than 2 characters returns False"""

    name = " P "
    result = User._validate_creation_data(valid_email, name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message == "Name must be at least 2 characters"


def test_validate_creation_data_with_too_long_name_returns_false(
    valid_email: str, valid_password: str
):
    """Test that _validate_creation_data() with name more than 2 characters returns False"""

    name = "Test" * 15
    result = User._validate_creation_data(valid_email, name, valid_password)
    is_valid, message = result

    assert isinstance(result, tuple)
    assert is_valid is False
    assert message == "Name must be at most 50 characters"
