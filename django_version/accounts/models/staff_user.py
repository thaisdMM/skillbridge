"""
StaffUser model for SkillBridge platform.

This module defines the concrete StaffUser model, representing platform
administrators and operators. StaffUser is the designated AUTH_USER_MODEL,
keeping administrative access separate from Client and Freelancer concerns.
"""

from accounts.models.base import BaseUser


class StaffUser(BaseUser):
    """
    Concrete user model representing a Staff operator in the SkillBridge platform.

    Inherits all authentication and identification functionality from BaseUser.
    This model creates the 'staff_users' table in the database, containing
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

    class Meta:
        verbose_name = "Staff User"
        verbose_name_plural = "Staff Users"
        db_table = "staff_users"
