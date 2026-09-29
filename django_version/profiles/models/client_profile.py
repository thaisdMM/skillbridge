"""
ClientProfile model for SkillBridge platform.

This module defines the concrete ClientProfile model, which extends
the base Profile model with client-specific attributes like company name, max budget, interests and website URL.
"""

import logging
from decimal import Decimal

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models.client import Client
from profiles.models.base import Profile
from profiles.models.skill import Skill

logger = logging.getLogger(__name__)


class ClientProfile(Profile):
    """
    Concrete profile model representing a client's profile in the platform.

    Extends the abstract Profile base class by adding fields specific to
    clients, such as their company name, max budget, interests and website URL.

    Attributes:
        Inherited from Profile:
            id: Auto-generated primary key
            bio: Short biography of the client (up to 500 characters)
            created_at: Timestamp when the profile was created
            updated_at: Timestamp when the profile was last updated

        Client-specific:
            user: One-to-one relationship with the client model
            company_name: Name of the client's company
            max_budget: Maximum budget the client is willing to pay for a project
            interests: Professional areas of interest the client is looking for
            website_url: URL link to the client's external website.
    """

    user = models.OneToOneField(
        Client,
        on_delete=models.PROTECT,
        related_name="profile",
        verbose_name=_("Client"),
        help_text=_("The client user associated with this profile."),
    )

    company_name = models.CharField(
        max_length=200,
        blank=True,
        verbose_name=_("Company Name"),
        help_text=_("Name of the client's company."),
    )

    max_budget = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_("Maximum Budget"),
        help_text=_("Maximum budget the client is willing to pay for a project."),
    )

    interests = models.ManyToManyField(
        Skill,
        blank=True,
        verbose_name=_("Interests"),
        help_text=_(
            "Professional areas of interest or skills that the client is looking for."
        ),
    )

    website_url = models.URLField(
        blank=True,
        verbose_name=_("Website URL"),
        help_text=_(
            "Link to the client's or company's external website. Optional, must be a valid URL if provided."
        ),
    )

    class Meta(Profile.Meta):
        verbose_name = _("Client Profile")
        verbose_name_plural = _("Client Profiles")
        db_table = "client_profiles"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Class name with profile ID, user ID, and max budget.
        """
        return (
            f"{self.__class__.__name__} (profile_id={self.id}, "
            f"user_id={self.user_id}, "
            f"max_budget={self.max_budget})"
        )

    def get_display_info(self) -> dict:
        """
        Return dictionary with display information for the client profile.

        Interests are returned as a list of skill names. If no interest have been
        added yet, an empty list is returned.

        Returns:
            dict: Dictionary containing name, max_budget, company_name,
            website_url, bio, and interests.

        Raises:
            ValueError: If called on an unsaved instance. The `interests`
                many-to-many relation cannot be used before the instance
                has a primary key.
        """
        return {
            "name": self.user.name,
            "max_budget": self.max_budget,
            "company_name": self.company_name,
            "website_url": self.website_url,
            "bio": self.bio,
            "interests": list(self.interests.values_list("name", flat=True)),
        }

    def clean(self) -> None:
        """
        Enforce ClientProfile validation invariants.

        Validates:
        - company_name must not be empty after stripping whitespace, if provided.
        - max_budget must be strictly greater than zero.
        - a profile cannot be created for an account that is inactive in the
          state being saved.

        Raises:
            ValidationError: If company_name is empty after stripping whitespace.
            ValidationError: If max_budget is zero or negative.
            ValidationError: If the profile is being created for an inactive
                client account.
        """
        super().clean()

        if self.company_name:
            logger.debug("Starting company_name validation - profile_id=%s", self.id)
            stripped_company_name = self.company_name.strip()
            if not stripped_company_name:
                logger.error("Company name validation failed - name cannot be empty.")
                raise ValidationError(
                    {
                        "company_name": ValidationError(
                            _("Company name cannot be empty."),
                            code="company_name_empty",
                        )
                    }
                )
            logger.debug("Company name validation successful")

        if self.max_budget is not None:
            logger.debug("Starting max_budget validation - profile_id=%s", self.id)
            if self.max_budget <= Decimal("0.00"):
                logger.error("Max budget validation failed - budget must be positive.")
                raise ValidationError(
                    {
                        "max_budget": ValidationError(
                            _("Max budget must be greater than zero."),
                            code="max_budget_not_positive",
                        )
                    }
                )
            logger.debug("Max budget validation successful")

        if self.pk is None:
            logger.debug("Starting account status validation on profile creation")
            account = self._get_account()
            if account is not None and not account.is_active:
                logger.error("Profile creation refused - account is inactive.")
                raise ValidationError(
                    {
                        "user": ValidationError(
                            _("A profile cannot be created for an inactive account."),
                            code="profile_for_inactive_account",
                        )
                    }
                )
            logger.debug("Account status validation successful")

    def _get_account(self) -> Client | None:
        """
        Return the client account attached to this profile, or None.

        Reads the in-memory instance rather than re-reading the database, so
        the status evaluated is the one being saved. During an admin save the
        inline formset sets the parent account on this instance before
        full_clean() runs, and that parent carries the submitted is_active
        value even when it has not been written yet.

        Returns:
            Client | None: The attached account, or None when no account is
                attached.
        """
        try:
            return self.user
        except ObjectDoesNotExist:
            return None
