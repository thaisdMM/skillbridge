"""
Freelancer model for SkillBridge platform.

This module defines the concrete Freelancer user model, inheriting authentication
and identification functionality from BaseUser and adding freelancer-specific
account fields.
"""

from __future__ import annotations
import logging

from django.db import models

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from accounts.models.base import BaseUser

logger = logging.getLogger(__name__)

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

    def clean(self) -> None:
        """
        Enforce business rule: an inactive freelancer cannot be marked as available.

        An inactive account is not visible to clients. Marking it as available
        would produce corrupted state — the freelancer would appear available
        but could not receive proposals.

        Raises:
            ValidationError: If is_active is False and is_available is True.
        """
        super().clean()
        if not self.is_active and self.is_available:
            logger.error("An inactive freelancer cannot be available.")
            raise ValidationError(
                {"is_available": ValidationError(
                    _(
                        "An inactive freelancer cannot be marked as available. "
                        "Activate the account first or set availability to unavailable."
                    ),
                    code="freelancer_inactive_available",
                )}
            )

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
        return f"{self.user_type.capitalize()}: {self.name} ({self.email})"

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
