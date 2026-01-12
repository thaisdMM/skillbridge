from __future__ import annotations

import logging
from datetime import datetime

from src.models.user import User
from src.utils.security import hash_password

logger = logging.getLogger(__name__)


class Freelance(User):
    """This is a Model class representing a user of the system as a freelance type

    This class is a subclass of User and inherits its attributes and methods.

    It includes methods for creatting a new freelance and reconstructing a existing freelance from storage.
    """

    def get_user_type(self) -> str:
        """Method to return the type of users system"""
        return "freelance"

    @classmethod
    def create(cls, email: str, password: str) -> Freelance:
        """Factory method to create a new freelance user with validate data.

            This method validates email and password before creating the instance,
            automatically hashes the password, and sets creation timestamp.

        Args:
            email: Email address of the new freelance user
            password: Plain text password (will be hashed automatically)

        Returns:
            Freelance: New freelance user instance

        Raises:
            ValueError: If email format is invalid or password doesn't meet requirements
        """
        logger.info("Creating a new freelancer user for %s", email)
        is_valid, error_message = cls._validate_creation_data(email, password)

        if not is_valid:
            logger.warning("Failed to create freelance: %s", error_message)
            raise ValueError(f"Failed to validate the data: {error_message}")

        hashed = hash_password(password)

        freelance_instance = cls(
            user_id=None,
            email=email,
            hashed_password=hashed,
            created_at=datetime.now(),
        )
        logger.info("Freelance user created successfully for: %s", email)
        return freelance_instance

    @classmethod
    def from_storage(
        cls,
        user_id: int,
        email: str,
        hashed_password: str,
        created_at: datetime,
    ):
        """Factory method to reconstruct freelance from storage.

        Reconstructs a Freelance instace from storage data withoud
        validating or re-hashing (data already validated when saved)

        Args:
            user_id: User unique identifier from database
            email: Stored email address
            hashed_password: Already hashed password from storage
            created_at: Original creation timestamp
        """
        logger.info("Reconstructing freelance user from storage: id=%s", user_id)
        return cls(
            user_id=user_id,
            email=email,
            hashed_password=hashed_password,
            created_at=created_at,
        )
