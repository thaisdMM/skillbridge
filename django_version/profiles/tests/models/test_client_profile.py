"""
Tests for ClientProfile model.

Verifies client profile model attributes, validations, and database behaviors.
"""

import time
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction

from accounts.models.client import Client
from profiles.models.base import Profile
from profiles.models.client_profile import ClientProfile
from profiles.models.skill import Skill


def test_client_profile_inherits_from_profile_class() -> None:
    """ClientProfile is a subclass of the abstract Profile base class."""
    assert issubclass(ClientProfile, Profile)


@pytest.mark.django_db
def test_client_profile_creation_and_saving(
    client_profile: ClientProfile,
) -> None:
    """A ClientProfile instance is created, saved, and retrievable from the database with its fields intact."""
    saved_profile = ClientProfile.objects.get(id=client_profile.id)
    assert saved_profile.id is not None
    assert saved_profile.bio == "Company looking for Python developer collaboration"
    assert saved_profile.company_name == "Client Company"
    assert saved_profile.max_budget == Decimal("500.00")
    assert saved_profile.website_url == "https://portfolio.example.com"
    assert saved_profile.created_at is not None
    assert saved_profile.updated_at is not None


@pytest.mark.django_db
@pytest.mark.parametrize(
    "invalid_budget",
    [
        Decimal("0.00"),
        Decimal("-10.50"),
    ],
)
def test_client_profile_raises_validation_error_with_non_positive_max_budget(
    valid_client_profile_data: dict, invalid_budget: Decimal
) -> None:
    """A max budget <= 0 raises a ValidationError with code 'max_budget_not_positive'."""
    profile = ClientProfile(
        **{
            **valid_client_profile_data,
            "max_budget": invalid_budget,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "max_budget" in exc_info.value.error_dict
    assert exc_info.value.error_dict["max_budget"][0].code == "max_budget_not_positive"


@pytest.mark.django_db
def test_client_profile_max_budget_none_passes_validation(
    valid_client_profile_data: dict,
) -> None:
    """full_clean() does not raise ValidationError when max_budget is None."""
    profile = ClientProfile(
        **{
            **valid_client_profile_data,
            "max_budget": None,
        }
    )
    profile.full_clean()

    assert profile.max_budget is None


@pytest.mark.django_db
def test_client_profile_raises_validation_error_with_empty_company_name(
    valid_client_profile_data: dict,
) -> None:
    """A company_name provided with only whitespace raises a ValidationError with code 'company_name_empty'."""
    profile = ClientProfile(**{**valid_client_profile_data, "company_name": "   "})

    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "company_name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["company_name"][0].code == "company_name_empty"


@pytest.mark.django_db
def test_client_profile_no_company_name_passes_validation(
    valid_client_profile_data: dict,
) -> None:
    """full_clean() does not raise ValidationError when company_name is not provided."""
    profile = ClientProfile(**{**valid_client_profile_data, "company_name": ""})
    profile.full_clean()
    assert profile.company_name == ""


@pytest.mark.django_db
def test_client_profile_optional_fields_can_be_omitted(
    client_user: Client,
) -> None:
    """A ClientProfile with only a user set passes full_clean()."""
    profile = ClientProfile(user=client_user)

    profile.full_clean()


@pytest.mark.django_db
def test_client_profile_str_representation(
    client_profile: ClientProfile,
) -> None:
    """__str__ returns the formatted class name and profile ID."""
    assert str(client_profile) == (f"ClientProfile (profile_id={client_profile.id})")


@pytest.mark.django_db
def test_client_profile_repr_representation(
    client_profile: ClientProfile,
) -> None:
    """__repr__ returns class name, profile ID, user ID, and max budget."""
    assert repr(client_profile) == (
        f"ClientProfile (profile_id={client_profile.id}, "
        f"user_id={client_profile.user.id}, "
        f"max_budget={client_profile.max_budget})"
    )


@pytest.mark.django_db
def test_client_profile_get_display_info(
    client_profile: ClientProfile,
) -> None:
    """get_display_info returns the complete data dict, including the list of interests names."""
    interest_tech = Skill.objects.create(
        name="Python", category=Skill.Category.TECHNOLOGY
    )
    client_profile.interests.add(interest_tech)

    display_info = client_profile.get_display_info()
    assert display_info == {
        "name": "Client User",
        "max_budget": Decimal("500.00"),
        "company_name": "Client Company",
        "website_url": "https://portfolio.example.com",
        "bio": "Company looking for Python developer collaboration",
        "interests": ["Python"],
    }


@pytest.mark.django_db
def test_client_profile_get_display_info_without_interests(
    client_profile: ClientProfile,
) -> None:
    """get_display_info returns an empty list for interests when none are associated."""
    display_info = client_profile.get_display_info()
    assert display_info["interests"] == []


def test_client_profile_get_display_info_on_unsaved_instance() -> None:
    """get_display_info() raises ValueError when called before the ClientProfile instance is saved."""
    unsaved_client_profile = ClientProfile(user=Client(name="Unsaved Client"))

    with pytest.raises(ValueError):
        unsaved_client_profile.get_display_info()


@pytest.mark.django_db
def test_client_profile_on_delete_protect(
    client_user: Client, client_profile: ClientProfile
) -> None:
    """Deleting a Client referenced by a ClientProfile raises ProtectedError (on_delete=PROTECT)."""
    with pytest.raises(models.ProtectedError):
        client_user.delete()


@pytest.mark.django_db
def test_client_profile_add_interests(client_profile: ClientProfile) -> None:
    """Interests added to a client profile persist correctly in the database."""
    python_interest = Skill.objects.create(
        name="Python", category=Skill.Category.TECHNOLOGY
    )
    django_interest = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )

    client_profile.interests.add(python_interest, django_interest)
    reloaded_profile = ClientProfile.objects.prefetch_related("interests").get(
        id=client_profile.id
    )
    assert python_interest in reloaded_profile.interests.all()
    assert django_interest in reloaded_profile.interests.all()
    assert reloaded_profile.interests.count() == 2


@pytest.mark.django_db
def test_client_profile_remove_interests(client_profile: ClientProfile) -> None:
    """Interests removed from a client profile persist correctly in the database."""
    python_interest = Skill.objects.create(
        name="Python", category=Skill.Category.TECHNOLOGY
    )
    django_interest = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )

    client_profile.interests.add(python_interest, django_interest)

    client_profile.interests.remove(python_interest)
    reloaded_profile = ClientProfile.objects.prefetch_related("interests").get(
        id=client_profile.id
    )
    assert python_interest not in reloaded_profile.interests.all()
    assert django_interest in reloaded_profile.interests.all()
    assert reloaded_profile.interests.count() == 1


@pytest.mark.django_db
def test_client_profile_created_at_is_set_on_creation(
    client_profile: ClientProfile,
) -> None:
    """created_at is populated when the instance is first saved."""
    assert client_profile.created_at is not None


@pytest.mark.django_db
def test_client_profile_updated_at_changes_on_save(
    client_profile: ClientProfile,
) -> None:
    """updated_at changes to a later timestamp on every save."""
    original_updated_at = client_profile.updated_at

    time.sleep(0.001)

    client_profile.bio = "Updated bio"
    client_profile.save()
    client_profile.refresh_from_db()

    assert client_profile.updated_at > original_updated_at


@pytest.mark.django_db
def test_client_profile_user_uniqueness(
    client_profile: ClientProfile, client_user: Client
) -> None:
    """Creating a second ClientProfile for the same user raises a unique ValidationError on the user field."""
    duplicate_profile = ClientProfile(user=client_user)

    with pytest.raises(ValidationError) as exc_info:
        duplicate_profile.full_clean()

    assert "user" in exc_info.value.error_dict
    assert exc_info.value.error_dict["user"][0].code == "unique"


@pytest.mark.django_db
def test_client_profile_user_uniqueness_enforced_at_database_level(
    client_profile: ClientProfile, client_user: Client
) -> None:
    """Creating a second ClientProfile for the same user without validation raises IntegrityError."""
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            ClientProfile.objects.create(user=client_user)


@pytest.mark.django_db
def test_client_profile_max_budget_accepts_null_at_database_level(
    client_user: Client,
) -> None:
    """Saving a ClientProfile with max_budget=None succeeds because the column accepts NULL."""
    profile = ClientProfile.objects.create(user=client_user, max_budget=None)
    reloaded_profile = ClientProfile.objects.get(id=profile.id)
    assert reloaded_profile.max_budget is None


def test_client_profile_ordering() -> None:
    """ClientProfile inherits ordering by -created_at from Profile.Meta."""
    assert ClientProfile._meta.ordering == ["-created_at"]


@pytest.mark.django_db
def test_client_profile_creation_refused_for_inactive_account(
    client_user: Client,
    valid_client_profile_data: dict,
) -> None:
    """Creating a profile for an inactive account raises a 'profile_for_inactive_account' ValidationError."""
    inactive_client = client_user
    inactive_client.is_active = False
    profile = ClientProfile(
        **{
            **valid_client_profile_data,
            "user": inactive_client,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        profile.full_clean()

    assert "user" in exc_info.value.error_dict
    assert exc_info.value.error_dict["user"][0].code == "profile_for_inactive_account"


@pytest.mark.django_db
def test_client_profile_creation_accepted_for_active_account(
    valid_client_profile_data: dict,
) -> None:
    """Creating a profile for an active account passes full_clean()."""
    profile = ClientProfile(**valid_client_profile_data)

    profile.full_clean()


@pytest.mark.django_db
def test_client_profile_edit_accepted_on_deactivated_account(
    client_profile: ClientProfile,
) -> None:
    """An existing profile stays editable once its account is deactivated (FR-030)."""
    client_profile.user.is_active = False
    client_profile.user.save()

    client_profile.bio = "Updated while the account is deactivated"
    client_profile.full_clean()
    client_profile.save()

    client_profile.refresh_from_db()
    assert client_profile.bio == "Updated while the account is deactivated"


@pytest.mark.django_db
def test_client_profile_clean_does_not_raise_when_no_account_attached() -> None:
    """clean() raises no RelatedObjectDoesNotExist when no account is attached."""
    profile = ClientProfile()

    profile.clean()
