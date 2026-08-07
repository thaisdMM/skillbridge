"""
Tests for Skill model.

Verifies skill model attributes, validations, and database constraints.
"""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from profiles.models.skill import Skill


def test_skill_str_representation() -> None:
    """Skill __str__ method returns the exact name of the skill."""
    skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)
    assert str(skill) == "Python"


def test_skill_repr_representation() -> None:
    """Skill __repr__ on an unsaved instance renders category as the TextChoices enum."""
    skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)
    assert (
        repr(skill)
        == "Skill (id=None, name='Python', category=Skill.Category.TECHNOLOGY)"
    )


@pytest.mark.django_db
def test_skill_repr_representation_after_reload() -> None:
    """Skill __repr__ after save and reload renders category as a plain string."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    reloaded_skill = Skill.objects.get(id=skill.id)
    assert repr(reloaded_skill) == (
        f"Skill (id={reloaded_skill.id}, name='Python', category='TECHNOLOGY')"
    )


@pytest.mark.django_db
def test_skill_clean_strips_whitespace() -> None:
    """Skill name is stripped of leading and trailing whitespace on clean."""
    skill = Skill(name="  Python  ", category=Skill.Category.TECHNOLOGY)
    skill.clean()
    assert skill.name == "Python"


@pytest.mark.parametrize(
    "invalid_name",
    [
        "",
        "   ",
    ],
)
def test_skill_clean_empty_name_raises_validation_error(invalid_name: str) -> None:
    """Skill name that is empty or whitespace-only raises a ValidationError with code 'skill_name_empty'."""
    skill = Skill(name=invalid_name, category=Skill.Category.TECHNOLOGY)
    with pytest.raises(ValidationError) as exc_info:
        skill.clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "skill_name_empty"


def test_skill_clean_none_name_passes_validation() -> None:
    """Skill clean() leaves a None name untouched and raises no ValidationError."""
    skill = Skill(name=None, category=Skill.Category.TECHNOLOGY)
    skill.clean()
    assert skill.name is None


@pytest.mark.django_db
def test_skill_clean_name_differing_only_in_case_raises_validation_error() -> None:
    """A name differing from an existing skill only in letter case raises 'skill_name_duplicate'."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    case_variant = Skill(name="python", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(ValidationError) as exc_info:
        case_variant.full_clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_skill_clean_strips_the_name_before_comparing_it_with_existing_skills() -> None:
    """A padded name matching an existing skill once stripped raises 'skill_name_duplicate'."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    padded_case_variant = Skill(name="  python  ", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(ValidationError) as exc_info:
        padded_case_variant.full_clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_skill_whose_name_did_not_change_passes_validation() -> None:
    """A saved skill whose name did not change passes full_clean()."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)

    skill.full_clean()


@pytest.mark.django_db
def test_skill_recased_in_place_is_stored_with_the_new_capitalization() -> None:
    """A saved skill renamed to its own name in another case is stored with that case."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)

    skill.name = "python"
    skill.full_clean()
    skill.save()

    skill.refresh_from_db()
    assert skill.name == "python"


@pytest.mark.django_db
def test_renaming_a_skill_onto_another_skills_name_raises_validation_error() -> None:
    """Renaming a saved skill onto a second saved skill's name, differing in case, raises 'skill_name_duplicate'."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    second_skill = Skill.objects.create(name="Django", category=Skill.Category.TECHNOLOGY)
    second_skill.name = "python"

    with pytest.raises(ValidationError) as exc_info:
        second_skill.full_clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_skill_creation_assigns_id() -> None:
    """Creating a Skill assigns a database primary key."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    assert skill.id is not None


@pytest.mark.django_db
def test_skill_is_persisted_and_retrievable() -> None:
    """A created Skill is persisted and retrievable with its correct fields."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)

    saved_skill = Skill.objects.get(id=skill.id)
    assert saved_skill.name == "Python"
    assert saved_skill.category == Skill.Category.TECHNOLOGY


@pytest.mark.django_db
def test_skill_name_uniqueness() -> None:
    """A name repeating an existing skill exactly raises 'skill_name_duplicate'."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    duplicate_skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(ValidationError) as exc_info:
        duplicate_skill.full_clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_skill_name_uniqueness_enforced_at_database_level() -> None:
    """Duplicate skill name inserted without validation raises IntegrityError."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)


@pytest.mark.django_db
def test_skill_case_insensitive_name_uniqueness_enforced_at_database_level() -> None:
    """A name differing only in case, inserted without validation, raises IntegrityError."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Skill.objects.create(name="python", category=Skill.Category.TECHNOLOGY)


@pytest.mark.django_db
def test_skill_ordering() -> None:
    """Skill instances are ordered alphabetically by category first, then by name."""
    Skill.objects.create(name="React", category=Skill.Category.TECHNOLOGY)
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    Skill.objects.create(name="SEO", category=Skill.Category.MARKETING)
    Skill.objects.create(name="Copywriting", category=Skill.Category.WRITING)

    skills = list(Skill.objects.all())

    expected_names = ["SEO", "Python", "React", "Copywriting"]
    actual_names = [skill.name for skill in skills]

    assert actual_names == expected_names
