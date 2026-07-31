"""Shared fixtures for profiles app tests."""

from decimal import Decimal

import pytest

from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.client_profile import ClientProfile
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
def freelancer_user(db) -> Freelancer:
    """
    Create and return a Freelancer instance saved in the test database.

    Returns:
        Freelancer: A saved Freelancer user instance.
    """
    return Freelancer.objects.create_user(
        email="freelancer@example.com",
        name="Freelancer User",
        password="SecurePass@123",
    )


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
def client_user(db) -> Client:
    """
    Create and return a Client instance saved in the test database.

    Returns:
        Client: A saved Client user instance.
    """
    return Client.objects.create_user(
        email="client@example.com",
        name="Client User",
        password="Secure!Pass@123",
    )


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
