import pytest
from datetime import datetime
from src.models.client import Client


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


#  TESTS CREATE
class TestClientCreate:
    """Test for Client class factory method 'create'"""

    def test_create_client_instance_with_valid_data(
        self, valid_email: str, valid_password: str
    ):
        """Test that create() with valid data initializes client instance correctly"""
        email = valid_email
        password = valid_password

        client = Client.create(email, password)

        assert isinstance(client, Client)
        assert client is not None
        assert client.email == email
        assert client._hashed_password != password
        assert client._hashed_password.startswith("$argon2id$")
        assert client.user_type == "client"
        assert client.user_id is None

    def test_create_with_invalid_email_raises_error(
        self, invalid_email: str, valid_password: str
    ):
        """Test that create() with invalid email raises an error with descriptive message"""

        with pytest.raises(ValueError) as exc_info:
            Client.create(invalid_email, valid_password)

        assert "email" in str(exc_info.value).lower()

    def test_create_with_invalid_password_raises_error(
        self, valid_email: str, invalid_password: str
    ):
        """Test that create() with invalid password raises an error with descriptive message"""

        with pytest.raises(ValueError) as exc_info:
            Client.create(valid_email, invalid_password)

        assert "password" in str(exc_info.value).lower()


class TestClientFromStorage:
    """Test for client class factory method 'from_storage' that reconstruct a client instance from storage"""

    def test_from_storage_client_instance_with_valid_data(
        self, valid_email: str, hashed_password: str
    ):
        """Test that from_storage() with valid data reconstructs a client instance correctly from storage"""
        user_id = 1
        email = valid_email
        hashed = hashed_password
        created_at = datetime(2025, 1, 1, 12, 0, 0)

        client = Client.from_storage(user_id, email, hashed, created_at)

        assert isinstance(client, Client)
        assert client is not None
        assert client.user_id == user_id
        assert client.email == email
        assert client._hashed_password == hashed
        assert client.created_at == created_at
        assert client.user_type == "client"


class TestClientInheritedMethods:
    """Test for methods inherited from User"""

    def test_verify_password_correct_password_retuns_true(
        self, valid_email: str, valid_password: str, hashed_password: str
    ):
        """Test if verify_password() returns True when password is correct and matches with hashed password"""

        client = Client.from_storage(1, valid_email, hashed_password, datetime.now())
        result = client.verify_password(valid_password)
        assert isinstance(result, bool)
        assert result is True

    def test_verify_password_wrong_password_retuns_false(
        self, valid_email: str, invalid_password: str, hashed_password: str
    ):
        """Test if verify_password() returns False when password is wrong and doesn't match with hashed password"""

        client = Client.from_storage(1, valid_email, hashed_password, datetime.now())
        result = client.verify_password(invalid_password)
        assert isinstance(result, bool)
        assert result is False
