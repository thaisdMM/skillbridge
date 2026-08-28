"""
StaffUser model for SkillBridge platform.

This module defines the concrete StaffUser model, representing platform
administrators and operators. StaffUser is the designated AUTH_USER_MODEL,
keeping administrative access separate from Client and Freelancer concerns.
"""

import logging
from typing import ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models.base import BaseUser

logger = logging.getLogger(__name__)


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
            is_superuser: Full administrative permissions

        Overrides:
            is_staff: Permission to access Django admin site (default=True for staff accounts)
    """

    is_staff = models.BooleanField(
        default=True,
        verbose_name="Staff Status",
        help_text=(
            "Designates whether this staff user can log into the Django admin site. "
            "Defaults to True for staff accounts."
        ),
    )

    class Meta:
        verbose_name = "Staff User"
        verbose_name_plural = "Staff Users"
        db_table = "staff_users"
        constraints: ClassVar[list[models.CheckConstraint]] = [
            models.CheckConstraint(
                condition=~models.Q(is_active=True, is_staff=False),
                name="staffuser_active_no_staff_status",
            )
        ]

    def clean(self) -> None:
        """
        Enforce business rule: an active staff user must have staff status.

        Delegates to BaseUser.clean() first - see base class, then enforces
        the StaffUser-specific active/staff invariant.

        StaffUser exists solely to access the Django admin. has_module_perms
        grants admin access only when is_active and is_staff are both True.
        An account with is_active=True and is_staff=False sits alive in the
        database but is permanently locked out of the admin — corrupted state.

        Raises:
            ValidationError: If is_active is True and is_staff is False.
        """
        super().clean()
        if self.is_active and not self.is_staff:
            logger.error("An active staff user must have staff status.")
            raise ValidationError(
                {
                    "is_staff": ValidationError(
                        _(
                            "An active staff user must have staff status. "
                            "Grant staff status or deactivate the account."
                        ),
                        code="staffuser_active_without_staff",
                    )
                }
            )
