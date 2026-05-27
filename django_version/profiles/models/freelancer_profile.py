"""
FreelancerProfile model for SkillBridge platform.

This module defines the concrete FreelancerProfile model, which extends
the base Profile model with freelancer-specific attributes like hourly rate,
skills, portfolio URL, and years of experience.
"""

from decimal import Decimal
import logging

from django.core.exceptions import ValidationError
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
        verbose_name=_("Hourly Rate"),
        help_text=_("Hourly rate of the freelancer in the platform's base currency."),
    )

    skills = models.ManyToManyField(
        Skill,
        blank=True,
        verbose_name=_("Skills"),
        help_text=_("Skills associated with this freelancer. At least one is required."),
    )

    portfolio_url = models.URLField(
        blank=True,
        verbose_name=_("Portfolio URL"),
        help_text=_("Link to the freelancer's external portfolio site. Optional, but cannot be blank if provided."),
    )

    years_of_experience = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Years of Experience"),
        help_text=_("Number of years of professional experience the freelancer has."),
    )

    class Meta:
        verbose_name = _("Freelancer Profile")
        verbose_name_plural = _("Freelancer Profiles")
        db_table = "freelancer_profiles"

    def __str__(self) -> str:
        """
        Return a friendly string representation of the freelancer profile.

        Returns:
            str: Representation with freelancer's name and email.
        """
        return f"Freelancer Profile: {self.user.name} ({self.user.email})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Class name with profile ID, user ID, and hourly rate.
        """
        return (
            f"{self.__class__.__name__} (profile_id={self.id}, "
            f"user_id={self.user.id}, "
            f"hourly_rate={self.hourly_rate})"
        )

    def clean(self) -> None:
        """
        Enforce FreelancerProfile validation invariants.

        Validates:
        - hourly_rate must be strictly greater than zero.
        - portfolio_url, if provided, cannot be an empty string.

        Note:
            ManyToManyField (skills) cannot be validated here because the
            relationship is only available after the instance is saved to
            the database. Skill presence must be enforced at the form or
            serializer level.

        Raises:
            ValidationError: If hourly_rate is zero or negative.
            ValidationError: If portfolio_url is an empty string.
        """
        super().clean()

        logger.debug("Starting hourly_rate validation - profile_id=%s", self.id)

        if self.hourly_rate is not None and self.hourly_rate <= Decimal("0.00"):
            logger.error(
                "Hourly rate validation failed - rate must be positive: hourly_rate=%s",
                self.hourly_rate,
            )
            raise ValidationError(
                {
                    "hourly_rate": ValidationError(
                        _("Hourly rate must be greater than zero."),
                        code="hourly_rate_not_positive",
                    )
                }
            )

        logger.debug("Hourly rate validation successful")

        logger.debug("Starting portfolio_url validation - profile_id=%s", self.id)

        if self.portfolio_url is not None and self.portfolio_url.strip() == "":
            logger.error(
                "Portfolio URL validation failed - empty string provided")
            raise ValidationError(
                {
                    "portfolio_url": ValidationError(
                        _("Portfolio URL cannot be an empty string. Leave the field blank or provide a valid URL."),
                        code="portfolio_url_empty_string",
                    )
                }
            )

        logger.debug("Portfolio URL validation successful")

    def get_display_info(self) -> dict:
        """
        Return dictionary with display information for the freelancer profile.

        Skills are returned as a list of skill names. If no skills have been
        added yet, an empty list is returned.

        Returns:
            dict: Dictionary containing name, email, hourly_rate,
                years_of_experience, portfolio_url, bio, and skills.
        """
        return {
            "name": self.user.name,
            "email": self.user.email,
            "hourly_rate": self.hourly_rate,
            "years_of_experience": self.years_of_experience,
            "portfolio_url": self.portfolio_url,
            "bio": self.bio,
            "skills": list(self.skills.values_list("name", flat=True)),
        }
