"""Shared fixtures for profiles app tests."""

import pytest

from profiles.models.base import Profile
from profiles.models.freelancer_profile import FreelancerProfile
from accounts.models.freelancer import Freelancer


class DummyProfile(Profile):
    """
    Concrete dummy implementation of the abstract Profile model for testing.

    This subclass implements get_display_info to provide concrete profile behavior.
    """

    class Meta:
        """Meta options for DummyProfile."""

        app_label = "profiles"

    def get_display_info(self) -> dict[str, str]:
        """
        Get display-friendly dictionary representation of the profile.

        Returns:
            dict[str, str]: The dummy display information.
        """
        return {"dummy": "info"}


class UnimplementedProfile(Profile):
    """
    Concrete dummy subclass of Profile that does not implement get_display_info.

    Used to test that NotImplementedError is raised appropriately on incomplete subclasses.
    """

    class Meta:
        """Meta options for UnimplementedProfile."""

        app_label = "profiles"


@pytest.fixture(scope="function")
def dummy_profile_class() -> type[DummyProfile]:
    """
    Fixture providing the DummyProfile subclass of Profile.

    Returns:
        type[DummyProfile]: The DummyProfile class.
    """
    return DummyProfile


@pytest.fixture(scope="function")
def unimplemented_profile_class() -> type[UnimplementedProfile]:
    """
    Fixture providing the UnimplementedProfile subclass of Profile.

    Returns:
        type[UnimplementedProfile]: The UnimplementedProfile class.
    """
    return UnimplementedProfile


@pytest.fixture(scope="function")
def dummy_profile() -> DummyProfile:
    """
    Fixture providing an unsaved instance of DummyProfile.

    Returns:
        DummyProfile: An unsaved DummyProfile instance.
    """
    return DummyProfile()


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
    from decimal import Decimal
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
