"""Password hashing utilities using Argon2id."""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Create a secure password hash using Argon2id.

    Args:
        password: Plain text password to hash

    Returns:
        Hashed password as string
    """
    return ph.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify if a plain text password matches the hashed password.

    Args:
        password: Plain text password to verify
        hashed_password: Previously hashed password

    Returns:
        True if password matches, False if password is incorrect

    Raises:
        InvalidHashError: If hash format is invalid (indicates data corruption)
        VerificationError: If verification fails for other technical reasons

    Note:
        Only VerifyMismatchError (wrong password) returns False.
        Other exceptions indicate system issues and should be handled by caller.
    """
    try:
        ph.verify(hashed_password, password)
        return True
    except VerifyMismatchError:
        # Expected: user typed wrong password
        return False


def check_password_needs_rehash(hashed_password: str) -> bool:
    """
    Check if the hashed password needs to be rehashed with updated parameters.

    Args:
        hashed_password: The hash to check

    Returns:
        True if rehashing is needed, False otherwise

    Note:
        Best practice is to check this after each successful authentication.
        If True, rehash the password and update the stored hash in the database.
    """
    return ph.check_needs_rehash(hashed_password)
