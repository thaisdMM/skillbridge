"""Shared fixtures for profiles app tests."""

import pytest

from profiles.models.base import Profile


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
