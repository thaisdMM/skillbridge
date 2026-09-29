"""
Tests for FreelancerProfile model.

Verifies freelancer profile model attributes, validations, and database behaviors.
"""

import time
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction

from accounts.models.freelancer import Freelancer
from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


def test_freelancer_profile_inherits_from_profile_class() -> None:
    """FreelancerProfile is a subclass of the abstract Profile base class."""
    assert issubclass(FreelancerProfile, Profile)


@pytest.mark.django_db
def test_freelancer_profile_creation_and_saving(
    freelancer_profile: FreelancerProfile,
) -> None:
    """A FreelancerProfile instance is created, saved, and retrievable from the database with its fields intact."""
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
    """years_of_experience defaults to 0 when not explicitly provided."""
    profile = FreelancerProfile.objects.create(
        user=freelancer_user,
        hourly_rate=Decimal("30.00"),
    )
    assert profile.years_of_experience == 0


@pytest.mark.django_db
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
    """An hourly rate <= 0 raises a ValidationError with code 'hourly_rate_not_positive'."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "hourly_rate": invalid_rate,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "hourly_rate" in exc_info.value.error_dict
    assert (
        exc_info.value.error_dict["hourly_rate"][0].code == "hourly_rate_not_positive"
    )


@pytest.mark.django_db
def test_freelancer_profile_str_representation(
    freelancer_profile: FreelancerProfile,
) -> None:
    """__str__ returns the formatted class name and profile ID."""
    assert str(freelancer_profile) == (
        f"FreelancerProfile (profile_id={freelancer_profile.id})"
    )


@pytest.mark.django_db
def test_freelancer_profile_repr_representation(
    freelancer_profile: FreelancerProfile,
) -> None:
    """__repr__ returns class name, profile ID, user ID, and hourly rate."""
    assert repr(freelancer_profile) == (
        f"FreelancerProfile (profile_id={freelancer_profile.id}, "
        f"user_id={freelancer_profile.user.id}, "
        f"hourly_rate={freelancer_profile.hourly_rate})"
    )


@pytest.mark.django_db
def test_freelancer_profile_get_display_info(
    freelancer_profile: FreelancerProfile,
) -> None:
    """get_display_info returns the complete data dict, including the list of skill names."""
    skill_tech = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    freelancer_profile.skills.add(skill_tech)

    display_info = freelancer_profile.get_display_info()
    assert display_info == {
        "name": "Freelancer User",
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
    """get_display_info returns an empty list for skills when none are associated."""
    display_info = freelancer_profile.get_display_info()
    assert display_info["skills"] == []


def test_freelancer_profile_get_display_info_on_unsaved_instance() -> None:
    """get_display_info() raises ValueError when called before the FreelancerProfile instance is saved."""
    unsaved_freelancer_profile = FreelancerProfile(
        user=Freelancer(name="Unsaved Freelancer")
    )

    with pytest.raises(ValueError):
        unsaved_freelancer_profile.get_display_info()


@pytest.mark.django_db
def test_freelancer_profile_on_delete_protect(
    freelancer_user: Freelancer, freelancer_profile: FreelancerProfile
) -> None:
    """Deleting a Freelancer referenced by a FreelancerProfile raises ProtectedError (on_delete=PROTECT)."""
    with pytest.raises(models.ProtectedError):
        freelancer_user.delete()


@pytest.mark.django_db
def test_freelancer_profile_add_skills(freelancer_profile: FreelancerProfile) -> None:
    """Skills added to a freelancer profile persist correctly in the database."""
    python_skill = Skill.objects.create(
        name="Python", category=Skill.Category.TECHNOLOGY
    )
    django_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )

    freelancer_profile.skills.add(python_skill, django_skill)
    reloaded_profile = FreelancerProfile.objects.prefetch_related("skills").get(
        id=freelancer_profile.id
    )
    assert python_skill in reloaded_profile.skills.all()
    assert django_skill in reloaded_profile.skills.all()
    assert reloaded_profile.skills.count() == 2


@pytest.mark.django_db
def test_freelancer_profile_remove_skills(
    freelancer_profile: FreelancerProfile,
) -> None:
    """Skills removed from a freelancer profile persist correctly in the database."""
    python_skill = Skill.objects.create(
        name="Python", category=Skill.Category.TECHNOLOGY
    )
    django_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )

    freelancer_profile.skills.add(python_skill, django_skill)

    freelancer_profile.skills.remove(python_skill)
    reloaded_profile = FreelancerProfile.objects.prefetch_related("skills").get(
        id=freelancer_profile.id
    )
    assert python_skill not in reloaded_profile.skills.all()
    assert django_skill in reloaded_profile.skills.all()
    assert reloaded_profile.skills.count() == 1


@pytest.mark.django_db
def test_freelancer_profile_created_at_is_set_on_creation(
    freelancer_profile: FreelancerProfile,
) -> None:
    """created_at is populated when the instance is first saved."""
    assert freelancer_profile.created_at is not None


@pytest.mark.django_db
def test_freelancer_profile_updated_at_changes_on_save(
    freelancer_profile: FreelancerProfile,
) -> None:
    """updated_at changes to a later timestamp on every save."""
    original_updated_at = freelancer_profile.updated_at

    time.sleep(0.001)

    freelancer_profile.bio = "Updated bio"
    freelancer_profile.save()
    freelancer_profile.refresh_from_db()

    assert freelancer_profile.updated_at > original_updated_at


@pytest.mark.django_db
def test_freelancer_profile_hourly_rate_none_passes_validation(
    valid_freelancer_profile_data: dict,
) -> None:
    """full_clean() does not raise when hourly_rate is None."""
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "hourly_rate": None,
        }
    )
    profile.full_clean()

    assert profile.hourly_rate is None


@pytest.mark.django_db
def test_freelancer_profile_optional_fields_can_be_omitted(
    freelancer_user: Freelancer,
) -> None:
    """A FreelancerProfile with only a user set passes full_clean()."""
    profile = FreelancerProfile(user=freelancer_user)

    profile.full_clean()


@pytest.mark.django_db
def test_freelancer_profile_hourly_rate_accepts_null_at_database_level(
    freelancer_user: Freelancer,
) -> None:
    """Saving a FreelancerProfile with hourly_rate=None succeeds because the column accepts NULL."""
    profile = FreelancerProfile.objects.create(user=freelancer_user, hourly_rate=None)
    reloaded_profile = FreelancerProfile.objects.get(id=profile.id)
    assert reloaded_profile.hourly_rate is None


@pytest.mark.django_db
def test_freelancer_profile_user_uniqueness(
    freelancer_profile: FreelancerProfile,
    freelancer_user: Freelancer,
) -> None:
    """A second FreelancerProfile for the same user raises a unique ValidationError on the user field."""
    duplicate_profile = FreelancerProfile(user=freelancer_user)

    with pytest.raises(ValidationError) as exc_info:
        duplicate_profile.full_clean()

    assert "user" in exc_info.value.error_dict
    assert exc_info.value.error_dict["user"][0].code == "unique"


@pytest.mark.django_db
def test_freelancer_profile_user_uniqueness_enforced_at_database_level(
    freelancer_profile: FreelancerProfile,
    freelancer_user: Freelancer,
) -> None:
    """Creating a second FreelancerProfile for the same user without validation raises IntegrityError."""
    with pytest.raises(IntegrityError), transaction.atomic():
        FreelancerProfile.objects.create(user=freelancer_user)


def test_freelancer_profile_ordering() -> None:
    """FreelancerProfile inherits ordering by -created_at from Profile.Meta."""
    assert FreelancerProfile._meta.ordering == ["-created_at"]


@pytest.mark.django_db
def test_freelancer_profile_creation_refused_for_inactive_account(
    freelancer_user: Freelancer,
    valid_freelancer_profile_data: dict,
) -> None:
    """Creating a profile for an inactive account raises a 'profile_for_inactive_account' ValidationError."""
    inactive_freelancer = freelancer_user
    inactive_freelancer.is_active = False
    inactive_freelancer.is_available = False
    profile = FreelancerProfile(
        **{
            **valid_freelancer_profile_data,
            "user": inactive_freelancer,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "user" in exc_info.value.error_dict
    assert exc_info.value.error_dict["user"][0].code == "profile_for_inactive_account"


@pytest.mark.django_db
def test_freelancer_profile_creation_accepted_for_active_account(
    valid_freelancer_profile_data: dict,
) -> None:
    """Creating a profile for an active account passes full_clean()."""
    profile = FreelancerProfile(**valid_freelancer_profile_data)

    profile.full_clean()


@pytest.mark.django_db
def test_freelancer_profile_edit_accepted_on_deactivated_account(
    freelancer_profile: FreelancerProfile,
) -> None:
    """An existing profile stays editable once its account is deactivated (FR-030)."""
    freelancer_profile.user.is_available = False
    freelancer_profile.user.is_active = False
    freelancer_profile.user.save()

    freelancer_profile.bio = "Updated while the account is deactivated"
    freelancer_profile.full_clean()
    freelancer_profile.save()

    freelancer_profile.refresh_from_db()
    assert freelancer_profile.bio == "Updated while the account is deactivated"


@pytest.mark.django_db
def test_freelancer_profile_clean_does_not_raise_when_no_account_attached() -> None:
    """clean() raises no RelatedObjectDoesNotExist when no account is attached."""
    profile = FreelancerProfile()

    profile.clean()
