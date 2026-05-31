"""
Tests for FreelancerProfile model.

Verifies freelancer profile model attributes, validations, and database behaviors.
"""

from decimal import Decimal

import pytest
import time
from django.core.exceptions import ValidationError
from django.db import models

from accounts.models.freelancer import Freelancer
from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


def test_freelancer_profile_inherits_from_profile_class() -> None:
    """Test that FreelancerProfile is a subclass of Profile abstract base class."""
    assert issubclass(FreelancerProfile, Profile)


@pytest.mark.django_db
def test_freelancer_profile_creation_and_saving(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that a FreelancerProfile instance can be created, saved, and successfully retrieved from the database."""
    saved_profile = FreelancerProfile.objects.get(id=freelancer_profile.id)
    assert saved_profile.id is not None
    assert saved_profile.bio == "Experienced Python developer looking for collaboration"
    assert saved_profile.hourly_rate == Decimal("50.00")
    assert saved_profile.portfolio_url == "https://portfolio.example.com"
    assert saved_profile.years_of_experience == 5
    assert saved_profile.created_at is not None
    assert saved_profile.updated_at is not None


@pytest.mark.django_db
def test_freelancer_profile_default_years_of_experience(
    freelancer_user: Freelancer,
) -> None:
    """Test that years_of_experience defaults to 0 when not explicitly provided."""
    profile = FreelancerProfile.objects.create(
        user=freelancer_user,
        hourly_rate=Decimal("30.00"),
    )
    assert profile.years_of_experience == 0


@pytest.mark.parametrize(
    "invalid_rate",
    [
        Decimal("0.00"),
        Decimal("-10.50"),
    ],
)
def test_freelancer_profile_raises_validation_error_with_non_positive_hourly_rate(
    valid_freelancer_profile_data: dict, invalid_rate: Decimal
) -> None:
    """Test that an hourly rate <= 0 raises a ValidationError with code 'hourly_rate_not_positive'."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "hourly_rate": invalid_rate,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.clean()

    assert "hourly_rate" in exc_info.value.error_dict
    assert exc_info.value.error_dict["hourly_rate"][0].code == "hourly_rate_not_positive"


@pytest.mark.parametrize(
    "invalid_url",
    [
        "   ",
        "",
    ],
)
def test_freelancer_profile_raises_validation_error_with_empty_portfolio_url(
    valid_freelancer_profile_data: dict, invalid_url: str
) -> None:
    """Test that an empty or whitespace-only portfolio_url raises a ValidationError with code 'portfolio_url_empty_string'."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "portfolio_url": invalid_url,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.clean()

    assert "portfolio_url" in exc_info.value.error_dict
    assert exc_info.value.error_dict["portfolio_url"][0].code == "portfolio_url_empty_string"


def test_freelancer_profile_portfolio_url_none_passes_validation(
    valid_freelancer_profile_data: dict,
) -> None:
    """Test that a portfolio_url of None passes validation cleanly."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "portfolio_url": None,
        }
    )
    profile.clean()
    assert profile.portfolio_url is None


@pytest.mark.django_db
def test_freelancer_profile_str_representation(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that __str__ returns formatted representation with name and email."""
    assert str(freelancer_profile) == "Freelancer Profile: Freelancer User (freelancer@example.com)"


@pytest.mark.django_db
def test_freelancer_profile_repr_representation(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that __repr__ returns structured class name, profile ID, user ID and hourly rate."""
    assert repr(freelancer_profile) == (
        f"FreelancerProfile (profile_id={freelancer_profile.id}, "
        f"user_id={freelancer_profile.user.id}, "
        f"hourly_rate={freelancer_profile.hourly_rate})"
    )


@pytest.mark.django_db
def test_freelancer_profile_get_display_info(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that get_display_info returns complete data dict including list of skills."""
    skill_tech = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    freelancer_profile.skills.add(skill_tech)

    display_info = freelancer_profile.get_display_info()
    assert display_info == {
        "name": "Freelancer User",
        "email": "freelancer@example.com",
        "hourly_rate": Decimal("50.00"),
        "years_of_experience": 5,
        "portfolio_url": "https://portfolio.example.com",
        "bio": "Experienced Python developer looking for collaboration",
        "skills": ["Python"],
    }


@pytest.mark.django_db
def test_freelancer_profile_get_display_info_without_skills(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that get_display_info returns an empty list for skills when none are associated."""
    display_info = freelancer_profile.get_display_info()
    assert display_info["skills"] == []


@pytest.mark.django_db
def test_freelancer_profile_on_delete_protect(
    freelancer_user: Freelancer, freelancer_profile: FreelancerProfile
) -> None:
    """Test that a Freelancer cannot be deleted while a FreelancerProfile references it (on_delete=PROTECT)."""
    with pytest.raises(models.ProtectedError):
        freelancer_user.delete()


@pytest.mark.django_db
def test_add_and_remove_skills(freelancer_profile: FreelancerProfile) -> None:
    """Test that skills can be added to and removed from a freelancer profile with database persistence verified."""
    python_skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    django_skill = Skill.objects.create(name="Django", category=Skill.Category.TECHNOLOGY)

    freelancer_profile.skills.add(python_skill, django_skill)
    reloaded_profile = FreelancerProfile.objects.prefetch_related("skills").get(id=freelancer_profile.id)
    assert python_skill in reloaded_profile.skills.all()
    assert django_skill in reloaded_profile.skills.all()
    assert reloaded_profile.skills.count() == 2

    freelancer_profile.skills.remove(python_skill)
    reloaded_profile = FreelancerProfile.objects.prefetch_related("skills").get(id=freelancer_profile.id)
    assert python_skill not in reloaded_profile.skills.all()
    assert django_skill in reloaded_profile.skills.all()
    assert reloaded_profile.skills.count() == 1


@pytest.mark.django_db
def test_freelancer_profile_timestamps_auto_set(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Test that created_at is set on creation and never changes, and updated_at changes on every save."""
    original_created_at = freelancer_profile.created_at
    original_updated_at = freelancer_profile.updated_at

    time.sleep(0.001)

    freelancer_profile.bio = "Updated bio"
    freelancer_profile.save()
    freelancer_profile.refresh_from_db()

    assert freelancer_profile.created_at == original_created_at
    assert freelancer_profile.updated_at > original_updated_at
