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
        hashed_password: str,
        created_at: datetime,
    ):
        self._user_id = user_id
        self._email = email
        self._hashed_password = hashed_password  # hashed
        self._created_at = created_at
        logger.debug(
            "%s instance created: email=%s, id=%s",
            self.__class__.__name__,
            self._email,
            self._user_id,
        )

    @property
    def user_id(self) -> int | None:
        return self._user_id

    @property
    def email(self) -> str:
        return self._email

    @property
    def created_at(self) -> datetime:
        return self._created_at

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

        logger.info("Password verification attempt for: %s", self._email)

        result = verify_password(password, self._hashed_password)

        if result:
            logger.info("Password verified successfully for: %s", self._email)

        else:
            logger.warning("Invalid password attempt for: %s", self._email)

        return result

    @abstractmethod
    def get_user_type(self) -> str:
        """Get the type of system users: if is freelancer or client"""
        pass

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
        """Returns a string with the user information like: type of user, user id and user email"""
        return f"{self.__class__.__name__} (id= {self._user_id}), email '{self._email}'"
