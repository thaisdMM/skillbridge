import pytest
from datetime import datetime

from src.models.freelancer import Freelancer


# Fixtures (reusable data)
@pytest.fixture
def valid_email():
    """Reusable valid email for tests"""
    return "test@email.com"


@pytest.fixture
def invalid_email():
    """Reusable invalid email for tests"""
    return "invalid_email.com"


@pytest.fixture
def valid_password():
    """Reusable valid password for tests"""
    return "Secure_Pass123!"


@pytest.fixture
def invalid_password():
    """Reusable invalid password for tests"""
    return "invalid_password"


@pytest.fixture
def hashed_password():
    "Reusable Password already hashed for tests"
    from src.utils.security import hash_password

    return hash_password("Secure_Pass123!")


#  TESTS CREATE
class TestFreelancerCreate:
    """Test for freelance user class factory method 'create'"""

    def test_create_freelancer_instance_with_valid_data(
        self, valid_email: str, valid_password: str
    ):
        """Test that create() with valid data initializes freelance user instance correctly"""
        email = valid_email
        password = valid_password

        freelancer = Freelancer.create(email, password)

        assert isinstance(freelancer, Freelancer)
        assert freelancer is not None
        assert freelancer.email == email
        assert freelancer._hashed_password != password
        assert freelancer._hashed_password.startswith("$argon2id$")
        assert freelancer.user_type == "freelance"
        assert freelancer.user_id is None

    def test_create_with_invalid_email_raises_error(
        self, invalid_email: str, valid_password: str
    ):
        """Test that create() with invalid email raises an error with descriptive message"""

        with pytest.raises(ValueError) as exc_info:
            Freelancer.create(invalid_email, valid_password)

        assert "email" in str(exc_info.value).lower()

    def test_create_with_invalid_password_raises_error(
        self, valid_email: str, invalid_password: str
    ):
        """Test that create() with invalid password raises an error with descriptive message"""

        with pytest.raises(ValueError) as exc_info:
            Freelancer.create(valid_email, invalid_password)

        assert "password" in str(exc_info.value).lower()


class TestFreelancerFromStorage:
    """Test for freelance user class factory method 'from_storage' that reconstruct a freelance user instance from storage"""

    def test_from_storage_freelancer_instance_with_valid_data(
        self, valid_email: str, hashed_password: str
    ):
        """Test that from_storage() with valid data reconstructs a freelance user instance correctly from storage"""
        user_id = 1
        email = valid_email
        hashed = hashed_password
        created_at = datetime(2025, 1, 1, 12, 0, 0)

        freelancer = Freelancer.from_storage(user_id, email, hashed, created_at)

        assert isinstance(freelancer, Freelancer)
        assert freelancer is not None
        assert freelancer.user_id == user_id
        assert freelancer.email == email
        assert freelancer._hashed_password == hashed
        assert freelancer.created_at == created_at
        assert freelancer.user_type == "freelance"


class TestFreelancerInheritedMethods:
    """Test for methods inherited from User"""

    def test_verify_password_correct_password_retuns_true(
        self, valid_email: str, valid_password: str, hashed_password: str
    ):
        """Test if verify_password() returns True when password is correct and matches with hashed password"""

        freelancer = Freelancer.from_storage(
            1, valid_email, hashed_password, datetime.now()
        )
        result = freelancer.verify_password(valid_password)
        assert isinstance(result, bool)
        assert result is True

    def test_verify_password_wrong_password_retuns_false(
        self, valid_email: str, invalid_password: str, hashed_password: str
    ):
        """Test if verify_password() returns False when password is wrong and doesn't match with hashed password"""

        freelancer = Freelancer.from_storage(
            1, valid_email, hashed_password, datetime.now()
        )
        result = freelancer.verify_password(invalid_password)
        assert isinstance(result, bool)
        assert result is False
