"""
Skill model for SkillBridge platform.

This module defines the Skill model, representing a tagged capability
that freelancers can associate with their profiles and clients can use
to filter job postings.
"""

import logging

from django.db import models
from django.db.models.functions import Lower
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


class Skill(models.Model):
    """
    Represents a skill that can be associated with freelancer profiles.

    Skills are managed by platform administrators and selected by freelancers
    — they are not created freely by users. This ensures consistent naming
    across the platform and enables reliable filtering and matching.

    Attributes:
        name: Unique skill name (e.g. 'Python', 'Figma', 'Copywriting').
        category: Area of service this skill belongs to.
    """

    # Type hint for Pylint
    id: int

    class Category(models.TextChoices):
        """
        Defines the area of service a skill belongs to.

        Used to group skills into broad service categories,
        enabling filtered search and matching between freelancers and job postings.

        Attributes:
            TECHNOLOGY: Programming, frameworks, and technical tools.
            DESIGN: Visual, UX, and creative design tools.
            WRITING: Content creation, copywriting, and translation.
            MARKETING: SEO, social media, and digital promotion.
        """

        TECHNOLOGY = "TECHNOLOGY", _("Technology")
        DESIGN = "DESIGN", _("Design")
        WRITING = "WRITING", _("Writing")
        MARKETING = "MARKETING", _("Marketing")

    name = models.CharField(
        max_length=100,
        unique=True,
        verbose_name=_("Name"),
        help_text=_(
            "Skill name as it appears on the platform (e.g. 'Python'). "
            "Skills are managed by admins — freelancers select from this list."
        ),
    )
    category = models.CharField(
        max_length=20,
        choices=Category.choices,
        verbose_name=_("Category"),
        help_text=_("Area of service this skill belongs to."),
    )

    class Meta:
        verbose_name = _("Skill")
        verbose_name_plural = _("Skills")
        db_table = "skills"
        ordering = ["category", "name"]
        constraints = [
            models.UniqueConstraint(
                Lower("name"), name="skill_unique_name_case_insensitive"
            )
        ]

    def __str__(self) -> str:
        """
        Return string representation for admin and shell display.

        Returns:
            str: The skill name.
        """
        return self.name

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Class name with id, name and category.
        """
        return (
            f"{self.__class__.__name__} (id={self.id}, "
            f"name={self.name!r}, "
            f"category={self.category!r})"
        )

    def clean(self) -> None:
        """
        Enforce skill validation invariants.

        Strips leading and trailing whitespace from the name, refuses a name
        left empty by the strip, and refuses a name another skill already
        carries when letter case is ignored. The name is kept as entered, with
        only the surrounding whitespace removed, and the skill being saved is
        left out of the comparison.

        Raises:
            ValidationError: If name is empty or only whitespace.
            ValidationError: If another skill already carries the name,
                ignoring letter case.
        """
        super().clean()

        logger.debug("Starting skill name validation")
        if self.name is not None:
            self.name = self.name.strip()

            if not self.name:
                logger.error("Skill name validation failed - name is empty after strip")
                raise ValidationError(
                    {
                        "name": ValidationError(
                            _("Skill name cannot be empty or only whitespace."),
                            code="skill_name_empty",
                        )
                    }
                )

            duplicate_exists = (
                Skill.objects.annotate(lower_name=Lower("name"))
                .filter(lower_name=Lower(models.Value(self.name)))
                .exclude(pk=self.pk)
                .exists()
            )

            if duplicate_exists:
                logger.error(
                    "Skill name validation failed - case-insensitive duplicate"
                    " of an existing skill name"
                )
                raise ValidationError(
                    {
                        "name": ValidationError(
                            _(
                                "A skill with this name already exists. Skill"
                                " names are compared ignoring letter case."
                            ),
                            code="skill_name_duplicate",
                        )
                    }
                )

        logger.debug("Skill name validation successful")
