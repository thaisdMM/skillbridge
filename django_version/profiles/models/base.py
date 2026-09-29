"""
Base profile model for SkillBridge platform.

This module defines the abstract base profile that will be inherited by
ClientProfile and FreelancerProfile models, providing common profile fields
and functionality.
"""

import logging
from typing import ClassVar

from django.core.validators import MaxLengthValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


class Profile(models.Model):
    """
    Abstract base profile model for SkillBridge platform.

    Provides common profile attributes and behaviors for Client and Freelancer profiles.
    Includes biography and timestamp tracking.

    This is an abstract model - concrete implementations are ClientProfile and FreelancerProfile.

    Attributes:
        bio: Short biography of the user (up to 500 characters).
        created_at: Timestamp when the profile was created.
        updated_at: Timestamp when the profile was last updated.
    """

    # Type hint for Pylint
    id: int

    bio = models.TextField(
        max_length=500,
        blank=True,
        validators=[MaxLengthValidator(500)],
        verbose_name=_("Biography"),
        help_text=_("Short user biography (max 500 characters)"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
        help_text=_("Timestamp when the user profile was created"),
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Updated At"),
        help_text=_("Timestamp when the user profile was last updated"),
    )

    class Meta:
        abstract = True
        verbose_name = _("Base Profile")
        verbose_name_plural = _("Base Profiles")
        ordering: ClassVar[list[str]] = ["-created_at"]

    def __str__(self) -> str:
        """
        String representation of the profile.

        Returns:
            str: Profile identity representation.
        """
        return f"{self.__class__.__name__} (profile_id={self.id})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Developer-friendly representation with class name and id.
        """
        return f"{self.__class__.__name__} (profile_id={self.id})"

    def get_display_info(self) -> dict:
        """
        Return dictionary with display information for the profile.

        Must be implemented by concrete profile subclasses.

        Returns:
            dict: Profile display information.

        Raises:
            NotImplementedError: If the subclass does not implement this method.
        """
        logger.error(
            "get_display_info called on abstract Profile or unimplemented subclass"
        )
        raise NotImplementedError(_("Subclasses must implement get_display_info()."))
