"""Session-wide pytest configuration for the SkillBridge test suite."""

import pytest


@pytest.fixture(scope="session")
def django_db_setup(django_db_setup, django_db_blocker) -> None:
    """Empty the seeded skill vocabulary once the test database exists.

    Overrides pytest-django's own session fixture. The rows inserted by the
    profiles seed data migration are deleted at session setup, outside the
    per-test transaction, so every test starts from an empty Skill table.

    Args:
        django_db_setup: pytest-django's session fixture, which builds the
            test database.
        django_db_blocker: pytest-django's database access guard.
    """
    from profiles.models.skill import Skill

    with django_db_blocker.unblock():
        Skill.objects.all().delete()
