from __future__ import annotations

import logging
from datetime import datetime

from src.models.user import User
from src.utils.security import hash_password


logger = logging.getLogger(__name__)


class Client(User):
    """Model class representing a client user in the system.

        This class is a subclass of User and inherits its attributes and methods.
        It includes factory methods for creating new clients and reconstructing existing clients from storage.

    Attibutes:
        Inherites all attibutes from User class(user_id, email, hashed_password, created_at, user_type)
    """

    def get_user_type(self) -> str:
        """Method to return the type of users system"""
        return "client"

    @classmethod
    def create(cls, email: str, password: str) -> Client:
        """Factory method to create a new client user with validate data.

            This method validates email and password before creating the instance,
            automatically hashes the password, and sets creation timestamp.

        Args:
            email: Email address of the new client user
            password: Plain text password (will be hashed automatically)

        Returns:
            freelancer: New client instance

        Raises:
            ValueError: if email format is invalid or password doesn't meet requirements
        """

        logger.info("Creating a new client user for: %s", email)

        is_valid, error_message = cls._validate_creation_data(email, password)
        if not is_valid:
            logger.warning("Failed to create a new client: %s", error_message)
            raise ValueError(f"Failed to validate the data: {error_message}")

        hashed = hash_password(password)

        client_instance = cls(
            user_id=None,
            email=email,
            hashed_password=hashed,
            created_at=datetime.now(),
        )
        logger.info("Client user created successfully for: %s", email)
        return client_instance

    @classmethod
    def from_storage(
        cls, user_id: int, email: str, hashed_password: str, created_at: datetime
    ) -> Client:
        """Factory method to reconstruct client from storage.

            Reconstructs a Client instance from storage data without
            validating or re-hashing (data already validated when saved).

        Args:
            user_id: User unique identifier from database
            email: Stored email address
            hashed_password: Already hashed password from storage
            created_at: Original creation timestamp

        Returns:
            Client: Reconstructed client instance
        """
        logger.info("Reconstructing client user from storage: id=%s", user_id)
        return cls(
            user_id=user_id,
            email=email,
            hashed_password=hashed_password,
            created_at=created_at,
        )
