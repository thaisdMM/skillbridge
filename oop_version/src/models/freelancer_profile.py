from __future__ import annotations

import logging
from typing import List, Optional
from src.models.profile import Profile
from src.protocols.user_protocols import UserProtocol

logger = logging.getLogger(__name__)


class FreelancerProfile(Profile):
    """
    Model class representing a freelance user profile in the system.

    This class is a subclass of Profile and inherits its attributes and methods.
    It implements the abstract method display_info().
    """

    def __init__(
        self,
        user: UserProtocol,
        bio: str,
        hourly_rate: float,
        skills: list[str],
        portfolio_url: Optional[str] = None,
    ):
        """
        Initialize FreelancerProfile with user data and professional information.

        Args:
            user: User object implementing UserProtocol interface
            bio: User biography text
            hourly_rate: Hourly rate in USD (must be positive)
            skills: List of professional skills (minimum 1 required)
            portfolio_url: Optional URL to portfolio/website

        Raises:
            TypeError: If user doesn't implement UserProtocol (from parent)
            ValueError: If validation fails (bio, rate, skills, URL)
        """
        super().__init__(user, bio)
        self.hourly_rate = hourly_rate

        self._skills = []
        for skill in skills:
            self.add_skill(skill)

        if portfolio_url is not None:
            portfolio_url = portfolio_url.strip()
            if not portfolio_url:
                logger.warning("Portfolio URL validation failed - cannot be empty")
                raise ValueError("Portfolio URL cannot be empty")

            if not portfolio_url.lower().startswith(("http://", "https://")):
                logger.warning("Portfolio URL validation failed - must use HTTP/HTTPS")
                raise ValueError("Portfolio URL must start with 'http://', 'https://'")

        self._portfolio_url = portfolio_url

        logger.info(
            "Freelancer profile initialized successfully - profile_id: %s",
            self.profile_id,
        )

    @property
    def hourly_rate(self) -> float:
        return self._hourly_rate

    @property
    def skills(self) -> list[str]:
        return self._skills.copy()

    @property
    def portfolio_url(self) -> Optional[str]:
        return self._portfolio_url

    @hourly_rate.setter
    def hourly_rate(self, rate: float):
        """
        Set hourly rate for a freelance user with validation.

        Args:
            rate: float rate value (> 0)

        Raises:
            ValueError: If rate is not positive
        """
        logger.debug("Validating hourly rate - profile_id: %s", self.profile_id)

        if rate <= 0:
            logger.warning("Hourly rate validation failed - value must be positive")
            raise ValueError("Hourly rate must be greater than zero")

        self._hourly_rate = rate
        logger.debug("Hourly rate validated successfully")

    def add_skill(self, skill: str) -> None:
        """
        Add skill to freelancer profile with validation and normalization.

        Normalizes skill name to Title Case and performs case-insensitive
        duplicate check. If skill already exists, silently ignores (idempotent).

        Args:
            skill: Skill name to add

        Raises:
            ValueError: If skill is empty or only whitespace
        """

        logger.debug(
            "Starting skill validation - profile_id: %s",
            self.profile_id,
        )

        if not skill or not skill.strip():
            logger.warning("Skill validation failed - value cannot be empty")
            raise ValueError("Skill cannot be empty")

        normalized_skill = skill.strip().title()

        if any(
            existing_skill.lower() == normalized_skill.lower()
            for existing_skill in self._skills
        ):
            logger.debug("Skill already exists - ignoring duplicate")
            return

        self._skills.append(normalized_skill)

        logger.info("Skill added successfully - total skills: %d", len(self._skills))

    def delete_skill(self, skill_to_delete: str) -> None:
        """
        Remove skill from freelancer profile (idempotent).

        Note: Cannot delete the last remaining skill to maintain profile validity.
        Add replacement skills before removing the final skill if needed.

        Args:
            skill_to_delete: Skill name to remove

        Raises:
            ValueError: If attempting to delete the last remaining skill
        """
        logger.debug("Starting skill removal - profile_id: %s", self.profile_id)

        normalized_skill = skill_to_delete.strip().title()
        original_skills_count = len(self._skills)

        # Check if this deletion would violate minimum requirement
        skill_matches = any(
            skill.lower() == normalized_skill.lower() for skill in self._skills
        )

        if original_skills_count == 1 and skill_matches:
            logger.warning(
                "Blocked deletion of last skill - profile_id: %s, skills: '%s'",
                self.profile_id,
                len(self._skills),
            )
            raise ValueError(
                "Cannot delete skill as it's the last remaining skill"
                "Freelancer profiles must maintain at least one skill."
                "Add a replacement skill before removing this one."
            )

        # Perform the actual deletion
        self._skills = [
            skill for skill in self._skills if skill.lower() != normalized_skill.lower()
        ]

        if len(self._skills) < original_skills_count:
            logger.info(
                "Skill deleted successfully - profile_id: %s, remaining skills: %d",
                self.profile_id,
                len(self._skills),
            )
            return

        logger.debug("Skill '%s' not found - no action taken", normalized_skill)

    def display_info(self) -> str:
        """
        Display formatted freelancer profile information.

        Returns:
            Formatted string containing user type, name, hourly rate,
            skills list, and portfolio URL (if available)
        """
        skills_list = ", ".join(self.skills)

        result = (
            f"{self.user.user_type.title()}: {self.user.name}\n"
            f"Hourly Rate: ${self.hourly_rate:.2f}/hr\n"
            f"Skills: {skills_list}\n"
            f"Biography: {self.bio}"
        )

        if self.portfolio_url:
            result += f"\nPortfolio: {self.portfolio_url}"

        return result
