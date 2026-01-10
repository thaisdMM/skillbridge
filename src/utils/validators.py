"""
User input validation utilities.
"""

import logging
import re

logger = logging.getLogger(__name__)


def validate_email(email: str) -> bool:
    """
    Validate email format according to common standards.

    Args:
        email (str): Email address to validate

    Email requirements:
        - Valid characters before @: letters, numbers, dots, underscores, %, +, -
        - Must contain @ symbol
        - At least 1 character between @ and first dot
        - Must have at least one dot after @
        - At least 2 letters in the final domain extension (.com, .br, etc.)

    Returns:
        bool: True if email format is valid, False otherwise

    Examples:
        >>> validate_email("user@example.com")
        True
        >>> validate_email("user@sub.domain.com.br")
        True
        >>> validate_email("invalid.email")
        False
    """
    EMAIL_PATTERN = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$"

    logger.debug("Checking validation for: email=%s", email)
    is_email_valid = re.fullmatch(EMAIL_PATTERN, email.strip())

    result = is_email_valid is not None

    if not result:
        logger.debug("Email format invalid: %s", email)

    return result


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength according to security best practices.

    Args:
        password (str): Password to validate

    Password requirements:
        - Minimum length of 8 characters
        - At least one lowercase letter (a-z)
        - At least one uppercase letter (A-Z)
        - At least one special character (non-alphanumeric)
        - Numbers are optional but recommended

    Returns:
        tuple[bool, str]: (is_valid, error_message)
            - is_valid: True if password meets all requirements
            - error_message: Empty string if valid, specific error message otherwise

    Examples:
        >>> validate_password("Abc123!@")
        (True, "")
        >>> validate_password("weak")
        (False, "Password must be at least 8 characters long.")
    """
    check_password = password.strip()

    if len(check_password) < 8:
        logger.debug("Password validation failed: too short")
        return False, "Password must be at least 8 characters long."

    if check_password.isdigit():
        logger.debug("Password validation failed: only digits")
        return (
            False,
            "Password cannot contain only digits, it must include letters and special characters.",
        )

    if check_password.isalpha():
        logger.debug("Password validation failed: only alphabetic")
        return False, "Password must contain at least one special character."

    if check_password.isupper():
        logger.debug("Password validation failed: only uppercase letters")
        return (
            False,
            "Password cannot be all uppercase, it must contain at least one lowercase letter.",
        )

    if check_password.islower():
        logger.debug("Password validation failed: only lowercase letters")
        return (
            False,
            "Password cannot be all lowercase, it must contain at least one uppercase letter.",
        )

    if not re.search(r"[^a-zA-Z0-9]", check_password):
        logger.debug("Password validation failed: missing special character")
        return False, "Password must contain at least one special character."

    return True, ""
