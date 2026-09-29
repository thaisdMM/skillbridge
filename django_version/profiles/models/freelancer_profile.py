"""
FreelancerProfile model for SkillBridge platform.

This module defines the concrete FreelancerProfile model, which extends
the base Profile model with freelancer-specific attributes like hourly rate,
skills, portfolio URL, and years of experience.
"""

import logging
from decimal import Decimal

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from accounts.models.freelancer import Freelancer
from profiles.models.base import Profile
from profiles.models.skill import Skill

logger = logging.getLogger(__name__)


class FreelancerProfile(Profile):
    """
    Concrete profile model representing a freelancer's profile in the platform.

    Extends the abstract Profile base class by adding fields specific to
    freelancers, such as their hourly rate, skills, portfolio URL, and
    professional experience.

    Attributes:
        Inherited from Profile:
            id: Auto-generated primary key
            bio: Short biography of the freelancer (up to 500 characters)
            created_at: Timestamp when the profile was created
            updated_at: Timestamp when the profile was last updated

        Freelancer-specific:
            user: One-to-one relationship with the Freelancer model
            hourly_rate: Hourly rate of the freelancer in the platform's base currency
            skills: Many-to-many relationship with available Skill objects
            portfolio_url: URL link to the freelancer's external portfolio
            years_of_experience: Number of years of experience the freelancer has
    """

    user = models.OneToOneField(
        Freelancer,
        on_delete=models.PROTECT,
        related_name="profile",
        verbose_name=_("Freelancer"),
        help_text=_("The freelancer user associated with this profile."),
    )

    hourly_rate = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_("Hourly Rate"),
        help_text=_("Hourly rate of the freelancer in the platform's base currency."),
    )

    skills = models.ManyToManyField(
        Skill,
        blank=True,
        verbose_name=_("Skills"),
        help_text=_("Skills associated with this freelancer."),
    )

    portfolio_url = models.URLField(
        blank=True,
        verbose_name=_("Portfolio URL"),
        help_text=_(
            "Link to the freelancer's external portfolio site. Optional; must be a valid URL if provided."
        ),
    )

    years_of_experience = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Years of Experience"),
        help_text=_("Number of years of professional experience the freelancer has."),
    )

    class Meta(Profile.Meta):
        verbose_name = _("Freelancer Profile")
        verbose_name_plural = _("Freelancer Profiles")
        db_table = "freelancer_profiles"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Class name with profile ID, user ID, and hourly rate.
        """
        return (
            f"{self.__class__.__name__} (profile_id={self.id}, "
            f"user_id={self.user_id}, "
            f"hourly_rate={self.hourly_rate})"
        )

    def get_display_info(self) -> dict:
        """
        Return dictionary with display information for the freelancer profile.

        Skills are returned as a list of skill names. If no skills have been
        added yet, an empty list is returned.

        Returns:
            dict: Dictionary containing name, hourly_rate,
                years_of_experience, portfolio_url, bio, and skills.

        Raises:
            ValueError: If called on an unsaved instance. The `skills`
                many-to-many relation cannot be used before the instance
                has a primary key.
        """
        return {
            "name": self.user.name,
            "hourly_rate": self.hourly_rate,
            "years_of_experience": self.years_of_experience,
            "portfolio_url": self.portfolio_url,
            "bio": self.bio,
            "skills": list(self.skills.values_list("name", flat=True)),
        }

    def clean(self) -> None:
        """
        Enforce FreelancerProfile validation invariants.

        Validates:
        - hourly_rate must be strictly greater than zero.
        - a profile cannot be created for an account that is inactive in the
          state being saved.

        Note:
            ManyToManyField (skills) cannot be validated here because the
            relationship is only available after the instance is saved to
            the database. Skill presence must be enforced at the form or
            serializer level.

        Raises:
            ValidationError: If hourly_rate is zero or negative.
            ValidationError: If the profile is being created for an inactive
                freelancer account.
        """
        super().clean()

        if self.hourly_rate is not None:
            logger.debug("Starting hourly_rate validation - profile_id=%s", self.id)
            if self.hourly_rate <= Decimal("0.00"):
                logger.error("Hourly rate validation failed - rate must be positive.")
                raise ValidationError(
                    {
                        "hourly_rate": ValidationError(
                            _("Hourly rate must be greater than zero."),
                            code="hourly_rate_not_positive",
                        )
                    }
                )
            logger.debug("Hourly rate validation successful")

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

    def _get_account(self) -> Freelancer | None:
        """
        Return the freelancer account attached to this profile, or None.

        Reads the in-memory instance rather than re-reading the database, so
        the status evaluated is the one being saved. During an admin save the
        inline formset sets the parent account on this instance before
        full_clean() runs, and that parent carries the submitted is_active
        value even when it has not been written yet.

        Returns:
            Freelancer | None: The attached account, or None when no account
                is attached.
        """
        try:
            return self.user
        except ObjectDoesNotExist:
            return None
