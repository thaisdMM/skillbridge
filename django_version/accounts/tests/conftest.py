"""Shared fixtures for accounts app tests."""

from decimal import Decimal

import pytest
from django.test import Client as DjangoTestClient

from accounts.models.client import Client
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser
from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


@pytest.fixture
def valid_user_data() -> dict[str, str]:
    """
    Valid data to create a generic user.

    Returns dict (not object) for flexibility in test creation.
    Allows unpacking: User.objects.create(**valid_user_data)
    """
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }


@pytest.fixture
def valid_freelancer_data(valid_user_data: dict[str, str]) -> dict[str, str | bool]:
    """
    Valid data to create a Freelancer user.

    Inherits from valid_user_data and adds Freelancer-specific fields.
    """
    return {
        **valid_user_data,
        "is_available": True,
    }


@pytest.fixture
def valid_client_data(valid_user_data: dict[str, str]) -> dict[str, str]:
    """
    Valid data to create a Client user.

    Client has no extra fields, so returns valid_user_data.
    """
    return valid_user_data


@pytest.fixture
def freelancer_user(db, valid_freelancer_data: dict[str, str | bool]) -> Freelancer:
    """Create and return a Freelancer instance saved in the test database."""

    return Freelancer.objects.create_user(**valid_freelancer_data)


@pytest.fixture
def client_user(db, valid_client_data: dict[str, str]) -> Client:
    """Create and return a Client instance saved in the test database."""

    return Client.objects.create_user(**valid_client_data)


@pytest.fixture
def admin_site_client(db, client) -> DjangoTestClient:
    """
    Return a test client signed in as an active staff superuser.

    Used by the tests that drive the real admin views rather than a formset
    built in isolation. Whether a refusal reaches the page is a property of
    the rendered response, so those tests need a request cycle to measure.
    """

    administrator = StaffUser.objects.create_superuser(
        email="administrator@example.com",
        name="Administrator",
        password="SecurePass@123",
    )
    client.force_login(administrator)
    return client


@pytest.fixture
def skill(db) -> Skill:
    """
    Create and return a Skill instance saved in the test database.

    The suite runs with --no-migrations, so profiles/migrations/0002_seed_skills.py
    never executes and the skills table starts empty. Admin tests that attach or
    filter by a skill create it through this fixture.
    """

    return Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)


@pytest.fixture
def freelancer_profile(db, freelancer_user: Freelancer) -> FreelancerProfile:
    """
    Create and return a populated FreelancerProfile saved for freelancer_user.

    Field values mirror the literals in profiles/tests/conftest.py so the same
    fixture name means the same object in both apps. They are hardcoded rather
    than composed from a valid_freelancer_profile_data dict because no test in
    this app overrides a profile field — see testing.md, "Exception — no
    override consumers".
    """

    return FreelancerProfile.objects.create(
        user=freelancer_user,
        hourly_rate=Decimal("50.00"),
        portfolio_url="https://portfolio.example.com",
        years_of_experience=5,
        bio="Experienced Python developer looking for collaboration",
    )


@pytest.fixture
def client_profile(db, client_user: Client) -> ClientProfile:
    """
    Create and return a populated ClientProfile saved for client_user.

    Field values mirror the literals in profiles/tests/conftest.py, hardcoded
    for the same reason as freelancer_profile above.
    """

    return ClientProfile.objects.create(
        user=client_user,
        max_budget=Decimal("500.00"),
        company_name="Client Company",
        website_url="https://portfolio.example.com",
        bio="Company looking for Python developer collaboration",
    )
