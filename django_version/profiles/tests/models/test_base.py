"""
Tests for abstract Profile base model.

Verifies model behaviors and validations without requiring a concrete database table.
"""

import pytest
from django.core.exceptions import ValidationError

from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.tests.conftest import UnimplementedProfile


def test_profile_is_abstract() -> None:
    """Profile base model is abstract and cannot be directly instantiated."""
    assert Profile._meta.abstract is True


@pytest.mark.django_db
def test_valid_bio_passes_validation(valid_freelancer_profile_data: dict) -> None:
    """Biography within the length limit passes full_clean() validation."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "bio": "Valid biography under 500 characters.",
        }
    )
    profile.full_clean()


@pytest.mark.django_db
def test_exactly_500_char_bio_passes_validation(
    valid_freelancer_profile_data: dict,
) -> None:
    """Biography of exactly 500 characters passes validation."""
    profile = FreelancerProfile(**{**valid_freelancer_profile_data, "bio": "a" * 500})
    profile.full_clean()


@pytest.mark.django_db
def test_exceeding_500_char_bio_raises_validation_error(
    valid_freelancer_profile_data: dict,
) -> None:
    """Biography exceeding 500 characters raises a max_length ValidationError."""
    profile = FreelancerProfile(**{**valid_freelancer_profile_data, "bio": "a" * 501})
    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "bio" in exc_info.value.error_dict
    assert exc_info.value.error_dict["bio"][0].code == "max_length"


def test_unimplemented_get_display_info_raises_not_implemented_error(
    unimplemented_profile: UnimplementedProfile,
) -> None:
    """Subclass not implementing get_display_info raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        unimplemented_profile.get_display_info()
