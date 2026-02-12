from __future__ import annotations

import logging
from typing import List, Optional
from src.models.profile import Profile
from src.protocols.user_protocols import UserProtocol

logger = logging.getLogger(__name__)


class ClientProfile(Profile):
    """
    Model class representing a client user profile in the system.

    This class is a subclass of Profile and inherits its attributes and methods.
    It implements the abstract method display_info().
    """

    MIN_BUDGET = 10.0

    def __init__(
        self,
        user: UserProtocol,
        bio: str,
        max_budget: float,
        interests: list[str],
        company_name: Optional[str] = None,
        portfolio_url: Optional[str] = None,
    ):
        """
        Initialize ClientProfile with user data and professional information.

        Args:
            user: User object implementing UserProtocol interface
            bio: User biography text
            max_budget: Max budget value in USD (must be >= 10)
            interests: List of professional interests (minimum 1 required)
            company_name: Name of the company (default: user.name)
            portfolio_url: Optional URL to portfolio/website

        Raises:
            TypeError: If user doesn't implement UserProtocol (from parent)
            ValueError: If validation fails (bio, max_budget, interests, URL)
        """
        super().__init__(user, bio)
        self.max_budget = max_budget

        self._interests = []
        for interest in interests:
            self.add_interest(interest)

        self.company_name = company_name

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
            "Client profile initialized successfully - profile_id: %s",
            self.profile_id,
        )

    @property
    def max_budget(self) -> float:
        return self._max_budget

    @property
    def company_name(self) -> str | None:
        return self._company_name

    @property
    def interests(self) -> list[str]:
        return self._interests.copy()

    @property
    def portfolio_url(self) -> Optional[str]:
        return self._portfolio_url

    @max_budget.setter
    def max_budget(self, budget: float):
        """
        Set maximun budget value offer for a client user with validation.
        Uses MIN_BUDGET class attribute for validation.

        Args:
            budget: float budget value >= minimum budget (self.MIN_BUDGET)

        Raises:
            ValueError: If budget is not equal to or greater than minimum budget
        """
        logger.debug("Starting max budget validation - profile_id: %s", self.profile_id)

        if budget < self.MIN_BUDGET:
            logger.warning(
                "Max budget validation failed - value must be >= %.2f", self.MIN_BUDGET
            )
            raise ValueError(f"Max budget invalid - must be >= {self.MIN_BUDGET}")

        self._max_budget = budget
        logger.debug("Max budget validation successful")

    @company_name.setter
    def company_name(self, name: str):
        """
        Set the company name for the client profile with validatin.

        Args:
            name: The name of the company

        Raises:
            ValueError: If the name is empty, only whitespaces or length < 2
        """
        logger.debug(
            "Starting company name validation - profile_id: %s", self.profile_id
        )

        if name is None:
            self._company_name = None
            logger.debug("Company name not provided - skipping validation")
            return

        name_stripped = name.strip()
        if not name_stripped:
            logger.warning("Company name validation failed - cannot be empty")
            raise ValueError("Company name cannot be empty")
        if len(name_stripped) < 2:
            logger.warning("Company name validation failed - too short")
            raise ValueError("Company name must be at least 2 characters")

        self._company_name = name_stripped
        logger.debug("Company name validation successful")

    def add_interest(self, interest: str) -> None:
        """
        Add interest skill that client is looking for to client profile with validation and normalization.

        Normalizes interest name to Title Case and performs case-insensitive
        duplicate check. If interest already exists, silently ignores (idempotent).

        Args:
            interest: Name of the interest to add

        Raises:
            ValueError: If interest is empty or only whitespace
        """

        logger.debug(
            "Starting interest validation - profile_id: %s",
            self.profile_id,
        )

        if not interest or not interest.strip():
            logger.warning("Interest validation failed - value cannot be empty")
            raise ValueError("Interest cannot be empty")

        normalized_interest = interest.strip().title()

        if any(
            existing_interest.lower() == normalized_interest.lower()
            for existing_interest in self._interests
        ):
            logger.debug("Interest already exists - ignoring duplicate")
            return

        self._interests.append(normalized_interest)

        logger.info(
            "Interest added successfully - total interests: %d", len(self._interests)
        )

    def delete_interest(self, interest_to_delete: str) -> None:
        """
        Remove interest from client profile (idempotent).

        Note: Cannot delete the last remaining interest to maintain profile validity.
        Add replacement interests before removing the final interest if needed.

        Args:
            interest_to_delete: interest name to remove

        Raises:
            ValueError: If attempting to delete the last remaining interest
        """
        logger.debug("Starting interest removal - profile_id: %s", self.profile_id)

        normalized_interest = interest_to_delete.strip().title()
        original_interests_count = len(self._interests)

        # Check if this deletion would violate minimum requirement
        interest_matches = any(
            interest.lower() == normalized_interest.lower()
            for interest in self._interests
        )

        if original_interests_count == 1 and interest_matches:
            logger.warning(
                "Blocked deletion of last interest - profile_id: %s, interests: '%s'",
                self.profile_id,
                len(self._interests),
            )
            raise ValueError(
                "Cannot delete interest as it's the last remaining interest"
                "Client profiles must maintain at least one interest. "
                "Add a replacement interest before removing this one."
            )

        # Perform the actual deletion
        self._interests = [
            interest
            for interest in self._interests
            if interest.lower() != normalized_interest.lower()
        ]

        if len(self._interests) < original_interests_count:
            logger.info(
                "Interest deleted successfully - profile_id: %s, remaining interests: %d",
                self.profile_id,
                len(self._interests),
            )
            return

        logger.debug("Interest '%s' not found - no action taken", normalized_interest)

    def display_info(self) -> str:
        """
        Display formatted client profile information.

        Returns:
            Formatted string containing user type, name, max budget,
            interests list, and portfolio URL (if available)
        """
        interests_list = ", ".join(self.interests)

        result = f"{self.user.user_type.title()}: {self.user.name}\n"
        company_display = self.company_name if self.company_name else "Not specified"
        result += f"Company: {company_display}\n"
        result += (
            f"Max budget: ${self.max_budget:.2f}/hr\n"
            f"Interests: {interests_list}\n"
            f"Biography: {self.bio}"
        )

        if self.portfolio_url:
            result += f"\nPortfolio: {self.portfolio_url}"

        return result
