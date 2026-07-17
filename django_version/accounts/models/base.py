"""
Base user model for SkillBridge platform.

This module defines the abstract base user that will be inherited by
Client and Freelancer models, providing common authentication and
identification functionality.
"""

import logging
from typing import Any

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager as DjangoBaseUserManager,
)
from django.db import models
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from accounts.validators.user_validators import (
    validate_email,
    validate_user_name,
    validate_strong_password,
)

logger = logging.getLogger(__name__)


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
            ValidationError: Raised in any of the following cases:
                - A field fails its custom validator (email, name, or password).
                - A model invariant fails during full_clean() (e.g. a non-staff
                  model assigned staff/superuser privileges,
                  code "invalid_staff_privileges").
                - The email already exists, surfaced by validate_unique() as a
                  ValidationError (code "unique") instead of a database
                  IntegrityError.
        """

        logger.info("Starting user creation process")
        logger.debug("Validating email")
        validate_email(email)

        logger.debug("Validating name")
        validate_user_name(name)

        if password:
            logger.debug("Validating password")
            validate_strong_password(password)

        email = self.normalize_email(email)
        logger.debug("Email normalized successfully")

        user = self.model(email=email, name=name.strip(), **extra_fields)

        if password:
            logger.debug("Starting hashing password")
            user.set_password(password)
            logger.debug("Password hashed successfully")
        else:
            logger.debug("No password provided - setting unusable password")
            user.set_unusable_password()

        user.full_clean()
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
            ValueError: If is_staff or is_superuser are not True.
            ValidationError: Propagated from create_user — raised in any of
                the following cases:
                - A field fails its custom validator (email, name, or password).
                - A model invariant fails during full_clean() (e.g. a superuser
                  without staff status, code "superuser_without_staff").
                - The email already exists, surfaced by validate_unique() as a
                  ValidationError (code "unique") instead of a database
                  IntegrityError.
        """

        logger.info("Starting superuser creation process")

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            logger.error("Superuser creation failed - is_staff must be True")
            raise ValueError("Superuser must have is_staff=True")

        if extra_fields.get("is_superuser") is not True:
            logger.error("Superuser creation failed - is_superuser must be True")
            raise ValueError("Superuser must have is_superuser=True")

        user = self.create_user(email, name, password, **extra_fields)
        logger.info("Superuser created successfully: id=%s", user.id)

        return user


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

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = ["name"]

    objects = BaseUserManager()

    class Meta:
        abstract = True
        verbose_name = "Base User"
        verbose_name_plural = "Base Users"
        ordering = ["-created_at"]

    @property
    def user_type(self) -> str:
        """
        Return the user type based on the concrete subclass.

        Returns:
            str: 'client', 'freelancer', or the sublcass name lowercased
        """
        return self.__class__.__name__.lower()

    def __str__(self) -> str:
        """
        String representation of the user.

        Returns:
            str: Non-sensitive string representation with class name and database ID.
        """
        return f"{self.user_type.capitalize()} (id={self.id})"

    def __repr__(self) -> str:
        """
        Return detailed string representation for debugging.

        Returns:
            str: Non-sensitive developer-friendly representation with class name and database ID.
        """
        return f"{self.__class__.__name__} (id={self.id})"

    def has_perm(self, perm: str, obj: Any = None) -> bool:
        """
        Check if user has a specific permission.

        Args:
            perm: Permission string to check
            obj: Optional object to check permission against

        Returns:
            bool: True if user is active and superuser, False otherwise
        """
        return self.is_active and self.is_superuser

    def has_module_perms(self, app_label: str) -> bool:
        """
        Check if user has permissions to view a specific app in Django admin.

        Args:
            app_label: Application label to check permissions for

        Returns:
            bool: True if user is active and staff, False otherwise
        """
        return self.is_active and self.is_staff

    def clean(self) -> None:
        """
        Enforce invariant rules for the user instance.

        Enforces:
        - A superuser must also have staff status.
        - Non-staff user models (Client, Freelancer) cannot have staff or superuser privileges.

        Raises:
            ValidationError: If the user is a superuser but does not have staff status,
                or if a non-staff user model is assigned staff or superuser privileges.
        """
        super().clean()
        if self.user_type != "staffuser":
            if self.is_staff or self.is_superuser:
                logger.error("Non-staff user type assigned staff/superuser privileges")
                raise ValidationError(
                    {
                        "is_staff": ValidationError(
                            _(
                                "Only staff users can have administrative or staff privileges."
                            ),
                            code="invalid_staff_privileges",
                        )
                    }
                )
        if self.is_superuser and not self.is_staff:
            logger.error("Superuser without staff status")
            raise ValidationError(
                {
                    "is_staff": ValidationError(
                        _("A superuser must also have staff status."),
                        code="superuser_without_staff",
                    )
                }
            )
