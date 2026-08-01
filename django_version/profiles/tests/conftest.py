"""Shared fixtures for profiles app tests."""

from decimal import Decimal

import pytest

from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.client_profile import ClientProfile
from profiles.models.skill import Skill
from accounts.models.freelancer import Freelancer
from accounts.models.client import Client


class UnimplementedProfile(Profile):
    """
    Concrete dummy subclass of Profile that does not implement get_display_info.

    Used to test that NotImplementedError is raised appropriately on incomplete subclasses.
    """

    class Meta:
        """Meta options for UnimplementedProfile."""

        app_label = "profiles"


@pytest.fixture(scope="function")
def unimplemented_profile() -> UnimplementedProfile:
    """
    Fixture providing an unsaved instance of UnimplementedProfile.

    Returns:
        UnimplementedProfile: An unsaved UnimplementedProfile instance.
    """
    return UnimplementedProfile()


@pytest.fixture
def valid_freelancer_data() -> dict[str, str | bool]:
    """
    Valid data to create a Freelancer user.

    Returns dict (not object) for flexibility in test creation.
    Allows overriding account fields the profile rules depend on:
    Freelancer.objects.create_user(**{**valid_freelancer_data, "is_active": False})

    Returns:
        dict[str, str | bool]: Valid Freelancer field values.
    """
    return {
        "email": "freelancer@example.com",
        "name": "Freelancer User",
        "password": "SecurePass@123",
        "is_available": True,
    }


@pytest.fixture
def freelancer_user(db, valid_freelancer_data: dict[str, str | bool]) -> Freelancer:
    """
    Create and return a Freelancer instance saved in the test database.

    Args:
        valid_freelancer_data: Valid field values for Freelancer creation.

    Returns:
        Freelancer: A saved Freelancer user instance.
    """
    return Freelancer.objects.create_user(**valid_freelancer_data)


@pytest.fixture
def valid_freelancer_profile_data(freelancer_user: Freelancer) -> dict:
    """
    Valid data to create a FreelancerProfile instance.

    Returns dict (not object) for flexibility in test creation.
    Allows unpacking: FreelancerProfile(**valid_freelancer_profile_data)

    Args:
        freelancer_user: A saved Freelancer instance to associate with the profile.

    Returns:
        dict: Valid FreelancerProfile field values.
    """
    return {
        "user": freelancer_user,
        "hourly_rate": Decimal("50.00"),
        "portfolio_url": "https://portfolio.example.com",
        "years_of_experience": 5,
        "bio": "Experienced Python developer looking for collaboration",
    }


@pytest.fixture
def freelancer_profile(db, valid_freelancer_profile_data: dict) -> FreelancerProfile:
    """
    Create and return a saved FreelancerProfile instance.

    Args:
        valid_freelancer_profile_data: Valid field values for FreelancerProfile creation.

    Returns:
        FreelancerProfile: A saved FreelancerProfile instance.
    """
    return FreelancerProfile.objects.create(**valid_freelancer_profile_data)


@pytest.fixture
def skill(db) -> Skill:
    """
    Create and return a Skill instance saved in the test database.

    The suite runs with --no-migrations, so profiles/migrations/0002_seed_skills.py
    never executes and the skills table starts empty. Tests that need a skill
    create it through this fixture.

    Returns:
        Skill: A saved Skill instance in the TECHNOLOGY category.
    """
    return Skill.objects.create(name="Python", category=Skill.Category.TECHNOLOGY)


@pytest.fixture
def valid_client_data() -> dict[str, str]:
    """
    Valid data to create a Client user.

    Returns dict (not object) for flexibility in test creation.
    Allows overriding account fields the profile rules depend on:
    Client.objects.create_user(**{**valid_client_data, "is_active": False})

    Returns:
        dict[str, str]: Valid Client field values.
    """
    return {
        "email": "client@example.com",
        "name": "Client User",
        "password": "Secure!Pass@123",
    }


@pytest.fixture
def client_user(db, valid_client_data: dict[str, str]) -> Client:
    """
    Create and return a Client instance saved in the test database.

    Args:
        valid_client_data: Valid field values for Client creation.

    Returns:
        Client: A saved Client user instance.
    """
    return Client.objects.create_user(**valid_client_data)


@pytest.fixture
def valid_client_profile_data(client_user: Client) -> dict:
    """
    Valid data to create a ClientProfile instance.

    Returns dict (not object) for flexibility in test creation.
    Allows unpacking: ClientProfile(**valid_client_profile_data)

    Args:
        client_user: A saved Client instance to associate with the profile.

    Returns:
        dict: Valid ClientProfile field values.
    """
    return {
        "user": client_user,
        "max_budget": Decimal("500.00"),
        "company_name": "Client Company",
        "website_url": "https://portfolio.example.com",
        "bio": "Company looking for Python developer collaboration",
    }


@pytest.fixture
def client_profile(db, valid_client_profile_data: dict) -> ClientProfile:
    """
    Create and return a saved ClientProfile instance.

    Args:
        valid_client_profile_data: Valid field values for ClientProfile creation.

    Returns:
        ClientProfile: A saved ClientProfile instance.
    """
    return ClientProfile.objects.create(**valid_client_profile_data)
