"""
Base user model for SkillBridge platform.

This module defines the abstract base user that will be inherited by
Client and Freelancer models, providing common authentication and
identification functionality.
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager as DjangoBaseUserManager,
)


from django.core.exceptions import ValidationError
from django.db import models

from accounts.validators.user_validators import (
    validate_email,
    validate_user_name,
    validate_strong_password,
)

logger = logging.getLogger(__name__)


# CUSTOM USER MANAGER (Factory for creating users)


class BaseUserManager(DjangoBaseUserManager):
    """
    Custom manager for creating and managing BaseUser instances.

    Provides user creation with custom validation for email, name, and password.
    Supports both regular users and superusers with appropriate permissions.
    """

    def create_user(
        self,
        email: str,
        name: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> BaseUser:
        """
        Create and save a regular user.

        Args:
            email: User's email address (will be the login identifier)
            name: User's display name
            password: Plain text password (will be hashed automatically)
            **extra_fields: Additional fields for subclasses

        Returns:
            BaseUser: The created user instance

        Raises:
            ValidationError: If data doesn't pass custom validators
        """

        logger.info("Starting user creation process")

        # validation

        logger.debug("Validating email")
        validate_email(email)

        logger.debug("Validating name")
        validate_user_name(name)

        # can create a account using google, github - without password
        if password:
            logger.debug("Validating password")
            validate_strong_password(password)

        # normalize and create

        email = self.normalize_email(email)
        logger.debug("Email normalized successfully")

        user = self.model(email=email, name=name.strip(), **extra_fields)

        # hash password

        if password:
            logger.debug("Starting hashing password")
            user.set_password(password)
            logger.debug("Password hashed successfully")

        user.save(using=self._db)

        logger.info("User created successfully: id=%s", user.id)

        return user

    def create_superuser(
        self,
        email: str,
        name: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> BaseUser:
        """
        Create and save a superuser (admin with all permissions).

        This method is called by 'python manage.py createsuperuser'.

        Args:
            email: Admin email address (will be the login identifier)
            name: Admin display name
            password: Admin plain text password (will be hashed automatically)
            **extra_fields: Additional fields for subclasses

        Returns:
            BaseUser: The created superuser instance

        Raises:
            ValueError: If is_staff or is_superuser are not True
        """

        logger.info("Starting superuser creation process")

        # Force admin permissions
        # setdefault: sets value only if not already present in extra_fields

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        # Validate that admin flags are correct

        if extra_fields.get("is_staff") is not True:
            logger.error("Superuser creation failed - is_staff must be True")
            raise ValueError("Superuser must have is_staff=True")

        if extra_fields.get("is_superuser") is not True:
            logger.error("Superuser creation failed - is_superuser must be True")
            raise ValueError("Superuser must have is_superuser=True")

        # Create user using create_user (reuse validation logic)

        user = self.create_user(email, name, password, **extra_fields)
        logger.info("Superuser created successfully: id=%s", user.id)

        return user


# Base User Model (abstract foundation for Client and Freelancer)


class BaseUser(AbstractBaseUser):
    """
    Abstract base user model for SkillBridge platform.

    Provides common authentication and identification functionality for all user types.
    Uses email as the unique identifier for authentication instead of username.

    This is an abstract model - concrete implementations are Client and Freelancer.

    Attributes:
        email: Unique email address used for authentication
        name: User's display name (2-50 characters)
        created_at: Account creation timestamp
        is_active: Account activation status
        is_staff: Permission to access Django admin
        is_superuser: Full administrative permissions
    """

    # Type hint for Pylint
    id: int

    email = models.EmailField(
        unique=True,
        max_length=255,
        verbose_name="Email address",
        help_text="Email address used for login and communication",
        validators=[validate_email],
    )

    name = models.CharField(
        max_length=50,
        verbose_name="Display Name",
        help_text="User's display name (2-50 characters)",
        validators=[validate_user_name],
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Created At",
        help_text="Timestamp when the user account was created",
    )

    # Admin/permission fields

    is_active = models.BooleanField(
        default=True,
        verbose_name="Active",
        help_text="Designates whether this user should be treated as active. "
        "Unselect this instead of deleting accounts.",
    )

    is_staff = models.BooleanField(
        default=False,
        verbose_name="Staff Status",
        help_text="Designates whether the user can log into the Django admin site",
    )

    is_superuser = models.BooleanField(
        default=False,
        verbose_name="Superuser Status",
        help_text="Designates that this user has all permissions without "
        "explicitly assigning them",
    )

    # DJANGO REQUIRED SETTINGS

    # Which field is used for login? (instead of 'username')
    USERNAME_FIELD = "email"

    # Which fields are required when creating superuser via CLI?
    # besides USERNAME_FIELD and password, which are always required
    REQUIRED_FIELDS = ["name"]

    # Connect our custom manager
    objects = BaseUserManager()

    # META OPTIONS

    class Meta:
        abstract = True
        verbose_name = "Base User"
        verbose_name_plural = "Base Users"
        ordering = ["-created_at"]  # Newest users first

    # PROPERTIES (Calculated fields, not stored in database)

    @property
    def user_type(self) -> str:
        """
        Return the user type based on the concrete subclass.

        Returns:
            str: 'client', 'freelancer', or 'unknown'
        """

        # hasattr checks if the instance has a related object
        if hasattr(self, "client"):
            return "client"
        elif hasattr(self, "freelancer"):
            return "freelancer"
        return "unknown"

    def __str__(self) -> str:
        """
        String representation of the user.

        This is displayed in Django admin and when you print(user).

        Returns:
            str: String with email and name of the user
        """
        return f"{self.email} ({self.name})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Developer-friendly representation with class name, id, email, and name
        """
        return (
            f"{self.__class__.__name__} (id={self.id}), "
            f"email='{self.email}', name='{self.name}'"
        )

    # PERMISSION METHODS (required for Django admin)

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        """
        Check if user has a specific permission.

        Args:
            perm: Permission string to check
            obj: Optional object to check permission against

        Returns:
            bool: True if user is superuser, False otherwise
        """
        return self.is_superuser

    def has_module_perms(self, app_label: str) -> bool:
        """
        Check if user has permissions to view a specific app in Django admin.

        Args:
            app_label: Application label to check permissions for

        Returns:
            bool: True if user is staff, False otherwise
        """
        return self.is_staff
