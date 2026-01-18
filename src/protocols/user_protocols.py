# src/protocols/user_protocols.py

from typing import Protocol, runtime_checkable
from datetime import datetime


@runtime_checkable
class UserProtocol(Protocol):
    """
    Protocol defining required User interface for Profile composition.

    Any object implementing these attributes/methods can be used
    with Profile classes, enabling flexible testing and future extensions.

    Required attributes:
        - user_id: Unique identifier (int or None)
        - email: Email address (str)
        - created_at: Creation timestamp (datetime)
        - user_type: User type string (str)

    Required methods:
        - verify_password(password: str) -> bool
    """

    @property
    def user_id(self) -> int | None:
        """Unique user identifier"""
        ...

    @property
    def email(self) -> str:
        """User email address"""
        ...

    @property
    def created_at(self) -> datetime:
        """User creation timestamp"""
        ...

    @property
    def user_type(self) -> str:
        """User type: 'freelancer' or 'client'"""
        ...

    def verify_password(self, password: str) -> bool:
        """
        Verify if password matches stored hash.

        Args:
            password: Plain text password to verify

        Returns:
            bool: True if password matches, False otherwise
        """
        ...
