"""
Tests for Skill model.

Verifies skill model attributes, validations, and database constraints.
"""

import pytest
from django.core.exceptions import ValidationError

from profiles.models.skill import Skill


# TESTS: Representation (No Database Required)


def test_skill_str_representation() -> None:
    """Skill __str__ method returns the exact name of the skill."""
    skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)
    assert str(skill) == "Python"


def test_skill_repr_representation() -> None:
    """Skill __repr__ method returns a detailed, formatted debug representation.

    Note: When the instance is unsaved, Django preserves the TextChoices object
    on the category attribute, so repr() renders Skill.Category.TECHNOLOGY
    without quotes. Once saved and reloaded from the database, the attribute
    becomes the plain string 'TECHNOLOGY'.
    """
    skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)
    assert repr(skill) == "Skill(id=None, name='Python', category=Skill.Category.TECHNOLOGY)"


# TESTS: Validation & Normalization via clean() (No Database Required)


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

    assert "skill" in exc_info.value.error_dict
    assert exc_info.value.error_dict["skill"][0].code == "skill_name_empty"


# TESTS: Database Constraints (Database Required)


@pytest.mark.django_db
def test_skill_creation_and_saving() -> None:
    """Skill instance is successfully created and saved to the database."""
    skill = Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    assert skill.id is not None

    saved_skill = Skill.objects.get(id=skill.id)
    assert saved_skill.name == "Python"
    assert saved_skill.category == Skill.Category.TECHNOLOGY


@pytest.mark.django_db
def test_skill_name_uniqueness() -> None:
    """Unique skill name constraint is enforced via Django's unique validation."""
    Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)
    duplicate_skill = Skill(name="Python", category=Skill.Category.TECHNOLOGY)

    with pytest.raises(ValidationError) as exc_info:
        duplicate_skill.full_clean()

    assert "name" in exc_info.value.error_dict
    assert exc_info.value.error_dict["name"][0].code == "unique"


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
