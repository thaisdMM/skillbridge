"""Manual test for logging configuration."""

from src.config.logging_config import setup_logging
from src.utils.validators import validate_email, validate_password
from src.utils.security import (
    hash_password,
    verify_password,
    check_password_needs_rehash,
)
import logging


# Setup logging with DEBUG leval to see everything
setup_logging(level=logging.DEBUG)

print("=== Testing Validators ===\n")

# Test email validation
print("Testing email validation:")

validate_email("valid@example.com")  # Should pass
validate_email("invalid_email")  # Should fail and log

print("\n=== Testing Password ===\n")

# Test password validation
print("Testing password validation:")
validate_password("StrongPass123!")  # Should pass
validate_password("weak")  # Should fail and log

print("\n=== Testing Security ===\n")

# Test password hashing
print("Testing password hashing:")
hashed = hash_password("TestPassword123!")

# Test password verification
print("\nTesting password verification:")
verify_password("TestPassword123!", hashed)  # Correct
verify_password("WrongPassword", hashed)  # Wrong

# Test password needs rehashing
print("\nTesting rehasing verification:")
hashed = hash_password("Senha@Forte321#")
check_password_needs_rehash(hashed)  # False
