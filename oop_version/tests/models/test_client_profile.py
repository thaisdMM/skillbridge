"""
Tests for Client user profile.
"""

from __future__ import annotations
import pytest
from datetime import datetime
from uuid import UUID
from typing import Optional

from src.models.client import Client
from src.models.client_profile import ClientProfile
from src.models.profile import Profile


@pytest.fixture
def valid_bio():
    """Reusable valid bio for test"""
    return """Client looking for collaboration"""


@pytest.fixture
def valid_client():
    """Reusable valid client user"""
    return Client.create("user@test.com", "User Name", "SecurePass123!")


@pytest.fixture
def valid_company_name():
    """Reusable valid company name"""
    return "Company Tech"


@pytest.fixture
def valid_max_budget():
    """Reusable valid hourly rate"""
    return 100.0


@pytest.fixture
def valid_interests():
    """Reusable valid interests list"""
    return ["Python"]


@pytest.fixture
def valid_portfolio_url():
    """Reusable valid portfolio url"""
    return "https://portfolio.example.com"


class TestClientProfileInitialization:
    """Test for Client Profile creation"""

    def test_client_profile_accepts_valid_requirements(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_company_name: Optional[str],
        valid_portfolio_url: Optional[str],
    ):
        """
        Test that Client profile is initialized with valid data

        Validates that:
        - Client profile implements all the attributes required by Profile abstract base class
        - Client profile implements all the attributes required by  ClientProfile class.
        """

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            company_name=valid_company_name,
            portfolio_url=valid_portfolio_url,
        )

        assert client_profile.user == valid_client
        assert client_profile.bio == valid_bio
        assert client_profile.max_budget == valid_max_budget
        assert client_profile.interests == valid_interests
        assert client_profile.company_name == valid_company_name
        assert client_profile.portfolio_url == valid_portfolio_url

        assert isinstance(client_profile, ClientProfile)
        assert isinstance(client_profile.max_budget, (int, float))
        assert isinstance(client_profile.created_at, datetime)
        assert isinstance(client_profile.profile_id, UUID)
        assert client_profile.created_at.tzinfo is not None

    def test_client_profile_accepts_none_company_name(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_portfolio_url: Optional[str],
    ):
        """Test that Client profile is initialized with declaring company_name as None"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            company_name=None,
            portfolio_url=valid_portfolio_url,
        )

        assert isinstance(client_profile, ClientProfile)
        assert client_profile.company_name is None

    def test_client_profile_is_initialized_without_company_name(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_portfolio_url: Optional[str],
    ):
        """Test that Client profile is initialized without declaring a company_name (its has a None default value)"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            portfolio_url=valid_portfolio_url,
        )

        assert isinstance(client_profile, ClientProfile)
        assert client_profile.company_name is None

    def test_client_profile_accepts_none_portfolio_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_company_name: Optional[str],
    ):
        """Test that Client profile is initialized with declaring portfolio_url as None"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            company_name=valid_company_name,
            portfolio_url=None,
        )

        assert isinstance(client_profile, ClientProfile)
        assert client_profile.portfolio_url is None

    def test_client_profile_is_initialized_without_portfolio_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_company_name: Optional[str],
    ):
        """Test that Client profile is initialized without declaring portfolio_url (its has None default value)"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            company_name=valid_company_name,
        )

        assert isinstance(client_profile, ClientProfile)
        assert client_profile.portfolio_url is None

    def test_client_profile_raises_value_error_with_empty_company_name(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """
        Test that Client profile is not initialized with empty company_name and raises ValueError
        This error occurs when company_name is explicitly provided as an empty string.
        """

        with pytest.raises(ValueError, match="Company name cannot be empty"):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=valid_interests,
                company_name="",
            )

    def test_client_profile_raises_value_error_with_whitespace_company_name(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """
        Test that Client profile with whitespace company_name is correctly stripped and is not initialized raising ValueError
        """

        with pytest.raises(ValueError, match="Company name cannot be empty"):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=valid_interests,
                company_name="   ",
            )

    def test_client_profile_raises_value_error_with_company_name_too_short(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """
        Test that Client profile with company_name too short is not initialized raises ValueError
        """

        with pytest.raises(
            ValueError, match="Company name must be at least 2 characters"
        ):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=valid_interests,
                company_name="x",
            )

    def test_client_profile_raises_value_error_with_empty_portfolio_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """
        Test that Client profile is not initialized with empty portfolio_url and raises ValueError
        This error occurs when portfolio_url is explicitly provided as an empty string.
        """

        with pytest.raises(ValueError, match="Portfolio URL cannot be empty"):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=valid_interests,
                portfolio_url="",
            )

    def test_client_profile_raises_value_error_with_incorrect_portfolio_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """
        Test that Client profile is not initialized with incorrect portfolio_url and raises ValueError
        This error occurs when portfolio_url is explicitly provided and starts with an incorrect url (does not start with http:// or https://)
        """

        with pytest.raises(
            ValueError, match="Portfolio URL must start with 'http://', 'https://'"
        ):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=valid_interests,
                portfolio_url="abc//invalid.portfolio.com",
            )

    def test_client_profile_raises_value_error_with_max_budget_less_than_minimum_allowed(
        self, valid_client: Client, valid_bio: str, valid_interests: list[str]
    ):
        """
        Test that Client profile is not initialized and raises ValueError with  max_budget less than the minimum allowed
        """

        with pytest.raises(ValueError) as exc_info:
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=9.0,
                interests=valid_interests,
            )
        assert "Max budget invalid" in str(exc_info.value)

    def test_client_profile_raises_value_error_without_interests(
        self, valid_client: Client, valid_bio: str, valid_max_budget: float
    ):
        """
        Test that Client profile is not initialized without interests and raises ValueError
        The error is raised in the method add_interest
        """

        with pytest.raises(ValueError, match="Interest cannot be empty"):
            ClientProfile(
                user=valid_client,
                bio=valid_bio,
                max_budget=valid_max_budget,
                interests=[""],
            )

    def test_client_profile_setter_max_budget_raises_value_error_without_minimum_budget(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """Test Client profile is initialized correctly, but max_budget setter raises ValueError if try to set max_budget less than minimum allowed"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
        )
        with pytest.raises(ValueError) as exc_info:
            client_profile.max_budget = 5.99

        assert "Max budget invalid" in str(exc_info.value)
        assert client_profile.max_budget == valid_max_budget


class TestClientProfileAddInterestValidation:
    """Test Client profile method add_interest()"""

    def test_client_profile_add_interest_with_valid_data(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
    ):
        """Test add_interest() normalized and add a valid new interest."""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Python"],
        )

        client_profile.add_interest("DJANGO")

        assert len(client_profile.interests) == 2
        assert client_profile.interests == ["Python", "Django"]

    def test_client_profile_add_interest_ignores_duplicate_case_insensitive(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
    ):
        """Test that add_interest() should ignore duplicates (case-insensitive)."""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Python"],
        )

        client_profile.add_interest("python")

        assert len(client_profile.interests) == 1
        assert client_profile.interests == ["Python"]


class TestClientProfileDeleteinterestValidation:
    """Test Client profile method delete_interest()"""

    def test_client_profile_delete_interest_with_valid_data(
        self, valid_client: Client, valid_bio: str, valid_max_budget: float
    ):
        """Test delete_interest() with valid interests works with case-insensitive"""
        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Python", "Postgres"],
        )

        client_profile.delete_interest("POSTGRES")

        assert len(client_profile.interests) == 1
        assert client_profile.interests == ["Python"]

    def test_client_profile_delete_interest_raises_error_when_deleting_last_interest(
        self, valid_client: Client, valid_bio: str, valid_max_budget: float
    ):
        """Test that delete_interest() should raise error when attempting to delete last interest."""
        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Postgres"],
        )
        with pytest.raises(ValueError) as exc_info:
            client_profile.delete_interest("postgres")

        assert "Add a replacement interest before removing this one." in str(
            exc_info.value
        )
        assert len(client_profile.interests) == 1
        assert client_profile.interests == ["Postgres"]

    def test_client_profile_delete_interest_idempotent_when_interest_not_exists(
        self, valid_client: Client, valid_bio: str, valid_max_budget: float
    ):
        """Test that delete_interest() should be idempotent when interest doesn't exist."""
        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Python", "Django"],
        )

        client_profile.delete_interest("Java")

        assert len(client_profile.interests) == 2
        assert client_profile.interests == ["Python", "Django"]


class TestClientProfileDisplayInfo:
    """Test Client profile implemented Profile abstract method display_info()"""

    def test_client_profile_display_info_with_complete_valid_data(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_company_name: Optional[str],
        valid_portfolio_url: Optional[str],
    ):
        """Test display_info() returns correctly formatted string with all fields include company name and portfolio url"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=["Python", "Django"],
            company_name=valid_company_name,
            portfolio_url=valid_portfolio_url,
        )
        result = client_profile.display_info()

        assert "Client: User Name" in result
        assert "$100.00/hr" in result
        assert "Python, Django" in result
        assert "Company Tech" in result
        assert "Client looking for collaboration" in result
        assert "https://portfolio.example.com" in result

    def test_client_profile_display_info_valid_data_without_company_name(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_portfolio_url: Optional[str],
    ):
        """Test display_info() returns correctly formatted string without company name"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            portfolio_url=valid_portfolio_url,
        )
        result = client_profile.display_info()

        assert isinstance(result, str)
        assert "Client: User Name" in result
        assert "$100.00/hr" in result
        assert "Python" in result
        assert "Company: Not specified" in result
        assert "Client looking for collaboration" in result
        assert "https://portfolio.example.com" in result

    def test_client_profile_display_info_valid_data_without_profile_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
        valid_company_name: Optional[str],
    ):
        """Test display_info() returns correctly formatted string without portfolio url"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
            company_name=valid_company_name,
        )
        result = client_profile.display_info()

        assert isinstance(result, str)
        assert "Client: User Name" in result
        assert "$100.00/hr" in result
        assert "Python" in result
        assert "Company Tech" in result
        assert "Client looking for collaboration" in result
        assert "Portfolio" not in result

    def test_client_profile_display_info_valid_data_without_company_name_and_portfolio_url(
        self,
        valid_client: Client,
        valid_bio: str,
        valid_max_budget: float,
        valid_interests: list[str],
    ):
        """Test display_info() returns correctly formatted string without company name and portfolio url"""

        client_profile = ClientProfile(
            user=valid_client,
            bio=valid_bio,
            max_budget=valid_max_budget,
            interests=valid_interests,
        )
        result = client_profile.display_info()

        assert isinstance(result, str)
        assert "Client: User Name" in result
        assert "$100.00/hr" in result
        assert "Python" in result
        assert "Company: Not specified" in result
        assert "Client looking for collaboration" in result
        assert "Portfolio" not in result


def test_client_profile_inherits_from_profile_class():
    """Test that ClientProfile should be a subclass of Profile"""

    assert issubclass(ClientProfile, Profile)
