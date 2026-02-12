"""Tests for password hashing utilities."""

import pytest
from argon2.exceptions import InvalidHashError
from src.utils.security import (
    hash_password,
    verify_password,
    check_password_needs_rehash,
)


class TestHashPassword:
    """Tests for hash_password function."""

    def test_hash_password_returns_string(self):
        """Test that hash_password returns a valid Argon2id string."""
        password = "Abc123!@"
        hashed = hash_password(password)

        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed.startswith("$argon2id$")

    def test_hash_password_generates_unique_hashes_with_salt(self):
        """
        Test that hashing the same password twice produces different hashes.
        This verifies that Argon2 generates different salts for each hash.
        """
        password = "Senha_Forte321#"

        hashed1 = hash_password(password)
        hashed2 = hash_password(password)

        assert isinstance(hashed1, str)
        assert isinstance(hashed2, str)
        assert hashed1.startswith("$argon2id$")
        assert hashed2.startswith("$argon2id$")
        assert hashed1 != hashed2


class TestVerifyPassword:
    """Tests for verify_password function."""

    def test_verify_password_succeeds_with_correct_password(self):
        """Test that correct password verification returns True."""
        password = "Abc123!@"
        hashed = hash_password(password)

        result = verify_password(password, hashed)

        assert result is True

    def test_verify_password_returns_false_with_incorrect_password(self):
        """Test that incorrect password verification returns False."""
        password = "Senha_Forte321#"
        wrong_password = "Senha_Forte312#"
        hashed = hash_password(password)

        result = verify_password(wrong_password, hashed)

        assert result is False

    def test_verify_password_invalid_hash_raises_error(self):
        """
        Test that invalid hash format raises InvalidHashError.
        This indicates data corruption and should be handled by caller.
        """
        password = "Abc123!@"
        invalid_hash = "Invalid_hash"

        with pytest.raises(InvalidHashError):
            verify_password(password, invalid_hash)


class TestCheckPasswordNeedsRehash:
    """Tests for check_password_needs_rehash function."""

    def test_check_password_needs_rehash_returns_bool(self):
        """Test that the function returns a boolean value."""
        password = "Senha@Forte321#"
        hashed = hash_password(password)

        result = check_password_needs_rehash(hashed)

        assert isinstance(result, bool)

    def test_check_password_needs_rehash_returns_false_with_current_params(self):
        """
        Test that recently hashed password does not need rehashing.
        Since we use default parameters, this should return False.
        """
        password = "TestPassword123!"
        hashed = hash_password(password)

        result = check_password_needs_rehash(hashed)

        assert result is False
