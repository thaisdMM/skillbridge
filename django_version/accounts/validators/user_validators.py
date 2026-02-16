"""
Custom validatos for user input.
Adapted fom OOP version with Django integration.
"""

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import logging

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
        ValidationError: If email format is invalid

    Examples:
        >>> validate_email("user@example.com")  # OK
        >>> validate_email("user@sub.domain.com.br")  # OK
        >>> validate_email("invalid.email")  # Raises ValidationError
    """
    EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"

    logger.debug("Starting email validation")

    email_stripped = value.strip()
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
    """
    Validate password strength according to security best practices.

    Password requirements:
        - Minimum length of 8 characters
        - At least one lowercase letter (a-z)
        - At least one uppercase letter (A-Z)
        - At least one special character (non-alphanumeric)
        - Numbers are optional but recommended

    Args:
        value: Password to validate

    Raises:
        ValidationError: If password doesn't meet security requirements

    Examples:
        >>> validate_strong_password("Abc123!@")  # OK
        >>> validate_strong_password("weak")  # Raises ValidationError
    """
    logger.debug("Starting password validation")

    password = value.strip()

    # Check minimum length
    if len(password) < 8:
        logger.debug("Password validation failed: too short")
        raise ValidationError(
            _("Password must be at least 8 characters long."),
            code="password_too_short",
        )

    # Check if only digits
    if password.isdigit():
        logger.debug("Password validation failed: only digits")
        raise ValidationError(
            _(
                "Password cannot contain only digits, it must include letters and special characters."
            ),
            code="password_only_digits",
        )

    # Check if only alphabetic
    if password.isalpha():
        logger.debug("Password validation failed: only alphabetic")
        raise ValidationError(
            _("Password must contain at least one special character."),
            code="password_no_special_char",
        )

    # Check if all uppercase
    if password.isupper():
        logger.debug("Password validation failed: only uppercase letters")
        raise ValidationError(
            _(
                "Password cannot be all uppercase, it must contain at least one lowercase letter."
            ),
            code="password_all_uppercase",
        )

    # Check if all lowercase
    if password.islower():
        logger.debug("Password validation failed: only lowercase letters")
        raise ValidationError(
            _(
                "Password cannot be all lowercase, it must contain at least one uppercase letter."
            ),
            code="password_all_lowercase",
        )

    # Check for special characters
    if not re.search(r"[^a-zA-Z0-9\s]", password):
        logger.debug("Password validation failed: missing special character")
        raise ValidationError(
            _(
                "Password must contain at least one special character "
                "(!@#$%^&*()_+-=[]{}|;:,.<>?~ etc.)."
            ),
            code="password_no_special_char",
        )

    logger.debug("Password validation successful")
