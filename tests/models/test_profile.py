"""
Tests for Profile base class (ABC).

Tests cover:
- UserProtocol validation
- Bio setter validation
- Read-only properties
- Abstract class behavior
"""

from __future__ import annotations
import pytest
from datetime import datetime
from uuid import UUID
from src.models.profile import Profile
from src.models.freelancer import Freelancer
from src.models.client import Client
from src.protocols.user_protocols import UserProtocol


@pytest.fixture
def valid_bio():
    """Reusable valid bio for tests."""
    return "Experienced professional looking for collaboration."


@pytest.fixture
def valid_email():
    """Reusable valid email for tests."""
    return "user@test.com"


@pytest.fixture
def valid_password():
    """Reusable valid password for tests."""
    return "SecurePass123!"


class TestProfileUserProtocolValidation:
    """Test suite for UserProtocol validation in Profile."""

    def test_profile_accepts_valid_freelancer_user(
        self, valid_bio: str, valid_email: str, valid_password: str
    ):
        """
        Test that Profile accepts valid Freelancer instance.

        Validates that:
        - Freelancer implements UserProtocol
        - Profile initialization succeeds
        - User reference is stored correctly
        - Generated attributes (profile_id, created_at) are valid
        """
        # Arrange
        freelancer = Freelancer.create(valid_email, valid_password)

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act
        profile = TestProfile(user=freelancer, bio=valid_bio)

        # Assert: Profile created successfully
        assert profile is not None
        assert profile.user == freelancer
        assert profile.user.email == valid_email
        assert profile.bio == valid_bio

        # Assert: UserProtocol implementation
        assert isinstance(freelancer, UserProtocol)

        # Assert: Generated attributes exist and are valid
        assert isinstance(profile.profile_id, UUID)
        assert isinstance(profile.created_at, datetime)
        assert profile.created_at.tzinfo is not None

    def test_profile_accepts_valid_client_user(
        self, valid_bio: str, valid_email: str, valid_password: str
    ):
        """
        Test that Profile accepts valid Client instance.

        Validates that:
        - Client implements UserProtocol
        - Profile initialization succeeds
        - User reference is stored correctly
        - Generated attributes (profile_id, created_at) are valid
        """
        # Arrange
        client = Client.create(valid_email, valid_password)

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act
        profile = TestProfile(user=client, bio=valid_bio)

        # Assert: Profile created successfully
        assert profile is not None
        assert profile.user == client
        assert profile.user.email == valid_email
        assert profile.bio == valid_bio

        # Assert: UserProtocol implementation
        assert isinstance(client, UserProtocol)

        # Assert: Generated attributes exist and are valid
        assert isinstance(profile.profile_id, UUID)
        assert isinstance(profile.created_at, datetime)
        assert profile.created_at.tzinfo is not None

    def test_profile_rejects_object_missing_attributes(self, valid_bio: str):
        """
        Test that Profile rejects objects missing required attributes.

        Validates that:
        - _validate_user_protocol catches missing attributes
        - TypeError is raised with clear message
        - Error message shows exactly what is missing
        """

        # Arrange: Object missing user_id and created_at
        class InvalidUser:
            email = "invalid@test.com"
            user_type = "invalid"

            def verify_password(self, password: str) -> bool:
                return True

        invalid_user = InvalidUser()

        class TestProfile(Profile):
            def display_info(self) -> str:
                return "Test"

        # Act & Assert
        with pytest.raises(TypeError) as exc_info:
            TestProfile(user=invalid_user, bio=valid_bio)

        error_message = str(exc_info.value)
        assert "UserProtocol" in error_message
        assert "Missing required members" in error_message
        assert "user_id" in error_message
        assert "created_at" in error_message

    def test_profile_rejects_object_missing_methods(self, valid_bio: str):
        """
        Test that Profile rejects objects missing required methods.

        Validates that:
        - _validate_user_protocol catches missing methods
        - TypeError is raised with clear message
        - Error message shows exactly what is missing
        """

        # Arrange: Object missing verify_password() method
        class InvalidUser:
            user_id = 1
            email = "invalid@test.com"
            created_at = datetime.now()
            user_type = "invalid"
            # Missing: verify_password() method

        invalid_user = InvalidUser()

        class TestProfile(Profile):
            def display_info(self) -> str:
                return "Test"

        # Act & Assert
        with pytest.raises(TypeError) as exc_info:
            TestProfile(user=invalid_user, bio=valid_bio)

        error_message = str(exc_info.value)
        assert "UserProtocol" in error_message
        assert "Missing required members" in error_message
        assert "verify_password" in error_message

    def test_profile_rejects_object_with_non_callable_method(self, valid_bio: str):
        """
        Test that Profile rejects objects where required method is not callable.

        Validates that:
        - verify_password() must be a callable method
        - TypeError is raised with clear message
        - Error message shows exactly what is missing
        """

        # Arrange: verify_password is not callable (it's a boolean)
        class InvalidUser:
            user_id = 1
            email = "invalid@test.com"
            created_at = datetime.now()
            user_type = "invalid"
            verify_password = True  # Not a function!

        invalid_user = InvalidUser()

        class TestProfile(Profile):
            def display_info(self) -> str:
                return "Test"

        # Act & Assert
        with pytest.raises(TypeError) as exc_info:
            TestProfile(user=invalid_user, bio=valid_bio)

        error_message = str(exc_info.value)
        assert "UserProtocol" in error_message
        assert "Missing required members" in error_message
        assert "verify_password" in error_message
        assert not callable(invalid_user.verify_password)


class TestProfileBioSetterValidation:
    """Test suite for bio setter validation in Profile class."""

    def test_bio_rejects_empty_string(self, valid_email: str, valid_password: str):
        """
        Test that Profile bio setter rejects empty string.

        Validates that:
        - Empty string ("") raises ValueError
        - Error message is clear and specific
        """
        # Arrange
        user = Freelancer.create(valid_email, valid_password)
        bio = ""

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act & Assert
        with pytest.raises(ValueError, match="Bio cannot be empty"):
            TestProfile(user, bio)

    def test_bio_rejects_whitespace_only(self, valid_email: str, valid_password: str):
        """
        Test that Profile bio setter rejects whitespace-only string.

        Validates that:
        - Whitespace-only string ("   ") raises ValueError
        - Error message is clear and specific
        """
        # Arrange
        user = Freelancer.create(valid_email, valid_password)
        bio = "   "

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act & Assert
        with pytest.raises(ValueError, match="Bio cannot be empty"):
            TestProfile(user, bio)

    def test_bio_rejects_none_value(self, valid_email: str, valid_password: str):
        """
        Test that Profile bio setter rejects None value.

        Validates that:
        - None value raises ValueError
        - Error message indicates invalid value
        """
        # Arrange
        user = Freelancer.create(valid_email, valid_password)
        bio = None

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act & Assert
        with pytest.raises(
            ValueError, match="Bio cannot be empty or without a valid value"
        ):
            TestProfile(user, bio)

    def test_bio_rejects_string_too_long(self, valid_email: str, valid_password: str):
        """
        Test that Profile bio setter rejects string exceeding max length.

        Validates that:
        - String with 501+ characters raises ValueError
        - Error message indicates "too long"
        - Max length is 500 characters
        """
        # Arrange
        user = Freelancer.create(valid_email, valid_password)
        bio = "a" * 501  # 501 characters

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act & Assert
        with pytest.raises(ValueError, match="Bio too long"):
            TestProfile(user, bio)

    def test_bio_strips_whitespace(self, valid_email: str, valid_password: str):
        """
        Test that Profile bio setter strips leading/trailing whitespace.

        Validates that:
        - Whitespace is removed from both ends
        - Internal whitespace is preserved
        - Bio is stored in cleaned format
        """
        # Arrange
        user = Client.create(valid_email, valid_password)
        bio = "   This is a test bio with whitespace    "
        expected_bio = "This is a test bio with whitespace"

        class TestProfile(Profile):
            def display_info(self) -> str:
                return f"Test Profile: {self.user.email}"

        # Act
        profile = TestProfile(user, bio)

        # Assert
        assert profile.bio == expected_bio


class TestProfileAbstractBehavior:
    """Test suite for Profile abstract class behavior."""

    def test_profile_cannot_be_instantiated_directly(
        self, valid_email: str, valid_password: str, valid_bio: str
    ):
        """
        Test that Profile (ABC) cannot be instantiated directly.

        Validates that:
        - Abstract class raises TypeError when instantiated
        - display_info() must be implemented by subclasses
        - Error message indicates abstract class/method
        """
        # Arrange
        user = Freelancer.create(valid_email, valid_password)

        # Act & Assert: Cannot instantiate ABC directly
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            Profile(user=user, bio=valid_bio)
