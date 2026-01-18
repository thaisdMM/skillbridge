from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from uuid import UUID, uuid4
from datetime import datetime, UTC
from src.protocols.user_protocols import UserProtocol

logger = logging.getLogger(__name__)


class Profile(ABC):
    """Abstract base class to users profiles"""

    def __init__(self, user: UserProtocol, bio: str) -> None:
        """
        Initialize Profile with user aggregation.

        Args:
            user: User object implementing UserProtocol interface
            bio: User biography text

        Raises:
            TypeError: If user doesn't implement UserProtocol
            ValueError: If bio validation fails
        """
        self._validate_user_protocol(user)
        self._user = user
        # receives @property that is already validate in setter method
        self.bio = bio
        self._profile_id = uuid4()
        self._created_at = datetime.now(UTC)

        logger.debug(
            "%s instance created: profile_id=%s",
            self.__class__.__name__,
            self.profile_id,
        )

        logger.info("Profile initialized successfully")

    def _validate_user_protocol(self, user: object) -> None:
        """
        Validate that user implements UserProtocol interface.

        Checks for required attributes and callable methods at runtime.
        Provides clear error messages if validation fails.
        This ensures duck typing compatibility with the protocol.

        Args:
            user: Object to validate

        Raises:
            TypeError: If user doesn't implement required interface
        """

        logger.debug("Validating user protocol for type: %s", type(user).__name__)

        # Mandatory attributes (properties)
        required_attrs = ["user_id", "email", "created_at", "user_type"]

        # Mandatory methods
        required_methods = ["verify_password"]

        # Verify attributes
        missing_attrs = [attr for attr in required_attrs if not hasattr(user, attr)]

        # Verify methods
        missing_methods = [
            method
            for method in required_methods
            if not hasattr(user, method) or not callable(getattr(user, method))
        ]

        # If missing something fail
        if missing_attrs or missing_methods:
            missing = missing_attrs + missing_methods

            logger.warning(
                "User validation failed. Missing: %s | Got type: %s",
                missing,
                type(user).__name__,
            )

            raise TypeError(
                f"User must implement UserProtocol interface. "
                f"Missing required members: {missing}. "
                f"Got: {type(user).__name__}"
            )

        logger.debug("User protocol validation successful")

    @property
    def user(self) -> UserProtocol:
        """Get associated user object"""
        return self._user

    @property
    def bio(self) -> str:
        """Get user biography"""
        return self._bio

    @property
    def profile_id(self) -> UUID:
        """Get profile unique identifier"""
        return self._profile_id

    @property
    def created_at(self) -> datetime:
        """Get profile creation timestamp"""
        return self._created_at

    @bio.setter
    def bio(self, value: str) -> None:
        """
        Set user biography with validation.

        Args:
            value: Biography text

        Raises:
            ValueError: If bio is empty or exceeds max length
        """
        logger.debug(
            "Setting bio - length: %d",
            len(value) if value else 0,
        )
        if not value or not value.strip():
            logger.warning("Bio validation fail: bio empty or without a valid value.")
            raise ValueError("Bio cannot be empty or without a valid value")

        if len(value) > 500:
            logger.warning("Bio validation fail: too long (%d chars)", len(value))
            raise ValueError("Bio too long (max is 500 chars)")

        self._bio = value.strip()

        logger.debug("Bio validation successful")

    @abstractmethod
    def display_info(self) -> str:
        """
        Display profile information in formatted string.

        Must be implemented by subclasses.

        Returns:
            str: Formatted profile information
        """
        pass
