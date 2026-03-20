"""
Freelancer model for SkillBridge platform.

This module defines the concrete Freelancer user model, inheriting authentication
and identification functionality from BaseUser and adding freelancer-specific
account fields.
"""

from __future__ import annotations

from django.db import models

from accounts.models.base import BaseUser


class Freelancer(BaseUser):
    """
    Concrete user model representing a freelancer in the SkillBridge platform.

    Inherits all authentication and identification functionality from BaseUser.
    Adds freelancer-specific account status fields used for platform-level control.

    This model creates the 'freelancers' table in the database, containing both
    inherited BaseUser columns and freelancer-specific columns.

    Attributes:
        Inherits from BaseUser:
            id: Auto-generated primary key
            email: Unique email address used for authentication
            name: User's display name (2-50 characters)
            created_at: Account creation timestamp
            is_active: Account activation status
            is_staff: Permission to access Django admin
            is_superuser: Full administrative permissions

        Freelancer-specific:
            is_available: Freelancer availability to accept new proposals
    """

    is_available = models.BooleanField(
        default=True,
        verbose_name="Available",
        help_text=(
            "Designates whether this freelancer is currently accepting new proposals. "
            "Freelancers can toggle this without deactivating their account."
        ),
    )

    objects = BaseUser.objects.__class__()

    class Meta:
        verbose_name = "Freelancer"
        verbose_name_plural = "Freelancers"
        db_table = "freelancers"

    def __str__(self) -> str:
        """
        Return string representation for admin and shell display.

        Returns:
            str: User type, name and email
        """
        return f"Freelancer: {self.name} ({self.email})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Class name with id, email and availability status
        """
        return (
            f"{self.__class__.__name__}(id={self.id}, "
            f"email='{self.email}', "
            f"is_available={self.is_available})"
        )
