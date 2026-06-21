"""
Client model for SkillBridge platform.

This module defines the concrete Client user model, inheriting authentication
and identification functionality from BaseUser.
"""

from accounts.models.base import BaseUser


class Client(BaseUser):
    """
    Concrete user model representing a Client in the SkillBridge platform.

    Inherits all authentication and identification functionality from BaseUser.

    This model creates the 'clients' table in the database, containing
    inherited BaseUser columns.

    Attributes:
        Inherits from BaseUser:
            id: Auto-generated primary key
            email: Unique email address used for authentication
            name: User's display name (2-50 characters)
            created_at: Account creation timestamp
            is_active: Account activation status
            is_staff: Permission to access Django admin
            is_superuser: Full administrative permissions
    """

    class Meta(BaseUser.Meta):
        verbose_name = "Client"
        verbose_name_plural = "Clients"
        db_table = "clients"
