"""
User input validator utilities
"""

import re


def validate_email(email: str) -> bool:
    """
    Validate email format.

    Args:
        email (str): Email to validate
        email must contain:
            - @ symbol
            - at least 2 letters after @ symbol
            - at least one dot after the @ symbol
            - at least 2 letters after dot

    Returns:
        bool: True if valid, False otherwise

    Examples:
        >>> validate_email("user@example.com")
        True
        >>> validate_email("invalid.email")
        False
    """

    email_pattern = (
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]{2,}(\.[a-zA-Z0-9-]{2,})*\.[a-zA-Z]{2,}$"
    )
    # fullmatch to verify the entire string to start to the end
    is_email_valid = re.fullmatch(email_pattern, email.strip())
    return is_email_valid is not None


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password format.

    Args:
        password (str): Password to validate
        password must contain:
            - minimum length of 8 characters
            - at least one lowercase letter
            - at least one uppercase letter
            - at least one special character

    Returns:
        tuple: [bool: True or False, str: message indicates if valid or error]

    Examples:
        >>> validate_password("Abc123!@")
        (True, "Password Valid")
        >>> validate_password(False, "Password must be at least 8 characters long.")
    """
    check_password = password.strip()
    if len(check_password) < 8:
        return False, "Password must be at least 8 characters long."
    if check_password.isdigit():
        return (
            False,
            "Password cannot be all digits, it must contain letters and special characters.",
        )
    if check_password.isalpha():
        return (
            False,
            "Password cannot be all letters, it must contain at least one special character.",
        )
    if check_password.isupper():
        return (
            False,
            "Password letters cannot be all upper, it must contain at least one lowercase letter.",
        )
    if check_password.islower():
        return (
            False,
            "Password letters cannot be all lower, it must contain at least one uppercase letter.",
        )
    if not re.search(r"[^a-zA-Z0-9]", check_password):
        return False, "Password must contain at least one special character."

    return True, "Password Valid"


emails = [
    "thais@email.com",
    "thais_email.com",
    "thais@email",
    "thais@.com",
    "user@domain..com",
    "@domain.com",
    "e@domain.com",
    "teste@e.com",
    "thais@email.com.br",
]

for email in emails:
    print(f"{email} = {validate_email(email)}")

# password = input("Password: ")
# print(validate_password(password))


password = [
    "12345678",
    "ABCDEFGH",
    "abcdefgh",
    "ABCD1234",
    "abcd1234",
    "ABCDabcd",
    "abcDEF_",
    "abcDEFgh_",
]
for value in password:
    print(f"senha: {value} = {validate_password(value)}")
