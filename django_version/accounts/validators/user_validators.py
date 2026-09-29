"""
Custom validatos for user input.
Adapted fom OOP version with Django integration.
"""

import logging
import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


def validate_email(value: str) -> None:
    """
    Validate email format according to SkillBridge standards.

    Email requirements:
        - Valid characters before @: letters, numbers, dots, underscores, %, +, -
        - Must contain @ symbol
        - At least 1 character between @ and first dot
        - Must have at least one dot after @
        - At least 2 letters in the final domain extension (.com, .br, etc.)

    Args:
        value: Email address to validate

    Raises:
        ValidationError: If email is empty or format is invalid

    Examples:
        >>> validate_email("user@example.com")  # OK
        >>> validate_email("user@sub.domain.com.br")  # OK
        >>> validate_email("invalid.email")  # Raises ValidationError
    """
    EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"

    logger.debug("Starting email validation")

    email_stripped = value.strip()

    if not email_stripped:
        logger.debug("Email validation failed - empty email")
        raise ValidationError(
            _("Email cannot be empty."),
            code="empty_email",
        )

    is_valid = re.fullmatch(EMAIL_PATTERN, email_stripped) is not None

    if not is_valid:
        logger.debug("Email validation failed - invalid format")
        raise ValidationError(
            _("Enter a valid email address."),
            code="invalid_email",
        )

    logger.debug("Email validation successful")


def validate_user_name(value: str) -> None:
    """
    Validate user name according to SkillBridge standards.

    Name requirements:
        - Cannot be empty
        - Minimum length of 2 characters
        - Maximum length of 50 characters

    Args:
        value: Name to validate

    Raises:
        ValidationError: If name doesn't meet requirements
    """
    logger.debug("Starting name validation")

    name_stripped = value.strip()

    if not name_stripped:
        logger.debug("Name validation failed - empty name")
        raise ValidationError(
            _("Name cannot be empty."),
            code="empty_name",
        )

    if len(name_stripped) < 2:
        logger.debug("Name validation failed - too short: %d", len(name_stripped))
        raise ValidationError(
            _("Name must be at least 2 characters long."),
            code="name_too_short",
        )

    if len(name_stripped) > 50:
        logger.debug("Name validation failed - too long: %d", len(name_stripped))
        raise ValidationError(
            _("Name must be at most 50 characters long."),
            code="name_too_long",
        )

    logger.debug("Name validation successful")


def validate_strong_password(value: str) -> None:
    """Validate password strength according to SkillBridge security rules.

    Password requirements:
        - Minimum length of 8 characters.
        - No whitespace anywhere, including leading or trailing.
        - At least one lowercase letter (a-z).
        - At least one uppercase letter (A-Z).
        - At least one special character (non-alphanumeric).
        - Digits are allowed but not required.

    Args:
        value: The raw password to validate. It is never stripped or
            normalized; any whitespace is rejected outright.

    Raises:
        ValidationError: If the password is shorter than 8 characters,
            contains any whitespace, lacks a lowercase letter, lacks an
            uppercase letter, or lacks a special character. Each failure
            carries a distinct error code.

    Examples:
        >>> validate_strong_password("Abc123!@")  # OK
        >>> validate_strong_password("abc123!@")  # Raises: no uppercase
        >>> validate_strong_password("ABC123!@")  # Raises: no lowercase
        >>> validate_strong_password("Abcdefgh")  # Raises: no special char
    """
    logger.debug("Starting password validation")

    if len(value) < 8:
        logger.debug("Password validation failed: too short, length=%d", len(value))
        raise ValidationError(
            _("Password must be at least 8 characters long."),
            code="password_too_short",
        )

    if re.search(r"\s", value):
        logger.debug("Password validation failed: contains whitespace")
        raise ValidationError(
            _("Password cannot contain spaces or whitespace characters."),
            code="password_contains_whitespace",
        )

    if value.isdigit():
        logger.debug("Password validation failed: only digits")
        raise ValidationError(
            _(
                "Password cannot be only digits. It must include at least one lowercase "
                "letter, one uppercase letter, and one special character."
            ),
            code="password_only_digits",
        )

    if not re.search(r"[a-z]", value):
        logger.debug("Password validation failed: no lowercase letter")
        raise ValidationError(
            _("Password must contain at least one lowercase letter."),
            code="password_missing_lowercase",
        )

    if not re.search(r"[A-Z]", value):
        logger.debug("Password validation failed: no uppercase letter")
        raise ValidationError(
            _("Password must contain at least one uppercase letter."),
            code="password_missing_uppercase",
        )

    if not re.search(r"[^a-zA-Z0-9]", value):
        logger.debug("Password validation failed: missing special character")
        raise ValidationError(
            _(
                "Password must contain at least one special character "
                "(!@#$%^&*()_+-=[]{}|;:,.<>?~ etc.)."
            ),
            code="password_no_special_char",
        )

    logger.debug("Password validation successful")
