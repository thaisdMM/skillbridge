from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)


class User(ABC):
    """Abstract base class for the system users"""

    def __init__(
        self,
        user_id: int | None,  # New user None: doesn't have id yet
        email: str,
        name: str,
        hashed_password: str,
        created_at: datetime,
    ):
        """
        Initialize User with essential data.

        Args:
            user_id: User identifier (None if new user)
            email: Email address of the user
            name: Display name for the user
            hashed_password: Already hashed password (hashing done by subclass factory methods)
            created_at: Timestamp of user creation
        """

        self._user_id = user_id
        self._email = email
        self._name = name
        self._hashed_password = hashed_password  # hashed
        self._created_at = created_at
        self._user_type = self.get_user_type()
        logger.debug(
            "%s instance created: id=%s, type=%s",
            self.__class__.__name__,
            self._user_id,
            self._user_type,
        )

    @property
    def user_id(self) -> int | None:
        return self._user_id

    @property
    def email(self) -> str:
        return self._email

    @property
    def name(self) -> str:
        return self._name

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def user_type(self) -> str:
        return self._user_type

    @abstractmethod
    def get_user_type(self) -> str:
        """Get the type of system users: if is freelance or client"""
        pass

    @classmethod
    def _validate_creation_data(
        cls, email: str, name: str, password: str
    ) -> tuple[bool, str]:
        """Validate data for user creation

        Args:
            email: Email address of the new user to verify
            password: Plain text password given for the new user to verify
            name: Display name for the user

        Returns:
            tuple[bool, str]: (is_valid, error_message)
            - is_valid: True if data meets all requirements, False otherwise
            - error_message: Empty sting if is_valid, specific error message otherwise
        """
        from src.utils.validators import validate_email, validate_password

        logger.debug("Starting data validation for user creation")
        logger.info("Starting email validation")

        email_is_valid = validate_email(email)
        if not email_is_valid:
            logger.debug("Email validation failed - invalid format")
            return False, "Invalid email"

        logger.info("Starting name validation")
        name_stripped = name.strip()
        if not name_stripped:
            logger.debug("Name validation failed - empty name: %d", len(name_stripped))
            return False, "Name cannot be empty"

        if len(name_stripped) < 2:
            logger.debug("Name validation failed - too short: %d", len(name_stripped))
            return False, "Name must be at least 2 characters"

        if len(name_stripped) > 50:
            logger.debug("Name validation failed - too long: %d", len(name_stripped))
            return False, "Name must be at most 50 characters"
        logger.debug("Name validation successful")

        logger.info("Starting password validation")
        # validate_password is tuple to be False has to
        password_is_valid, password_error = validate_password(password)
        if not password_is_valid:
            logger.debug("Password validation failed")
            return False, password_error

        logger.debug("User data validation successful")
        return True, ""

    # concrete method = the same for all
    def verify_password(self, password: str) -> bool:
        """Method to check if password matchs with hashed password registered using the security function 'verify_password'

        Args:
            password: Plain text password given for the user to verify

        Returns:
            True if correct, False if password is incorrect

        Raises:
            InvalidHashError: If hash format is invalid (indicates data corruption)
            VerificationError: If verification fails for other technical reasons
        """
        from src.utils.security import verify_password

        logger.info("Starting password verification")

        result = verify_password(password, self._hashed_password)

        if result:
            logger.info("Password verification successful")

        else:
            logger.warning("Password verification failed")

        return result

    def __eq__(self, other: User) -> bool:
        """Compares if the user is the same by user's id

        Args:
            other: User instance

        Returns:
            False if other is not a User instance or if user_id is not the same of other_user_id
            True if user_id is the same as other_user_id

        """
        if not isinstance(other, User):
            logger.debug("Comparison with non-User type: %s", type(other).__name__)
            return False
        result = self._user_id == other._user_id

        logger.debug(
            "User comparison for %s == %s, result=%s",
            self._user_id,
            other._user_id,
            result,
        )

        return result

    def __repr__(self) -> str:
        """Returns a string with the user information like: type of user, user id, name and user email"""
        return f"{self.__class__.__name__} (id= {self._user_id}), name '{self._name}',  email '{self._email}'"
