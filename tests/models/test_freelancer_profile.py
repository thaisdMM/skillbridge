"""
Tests for Freelancer user profile.
"""

from __future__ import annotations
import pytest
from datetime import datetime
from uuid import UUID
from typing import Optional

from src.models.freelancer import Freelancer
from src.models.freelancer_profile import FreelancerProfile
from src.models.profile import Profile


@pytest.fixture
def valid_bio():
    """Reusable valid bio for test"""
    return """Experienced Python developer looking for collaboration"""


@pytest.fixture
def valid_freelancer():
    """Reusable valid freelance user"""
    return Freelancer.create("user@test.com", "SecurePass123!")


@pytest.fixture
def valid_hourly_rate():
    """Reusable valid hourly rate"""
    return 50.0


@pytest.fixture
def valid_skills():
    """Reusable valid skills list"""
    return ["Python"]


@pytest.fixture
def valid_portfolio_url():
    """Reusable valid portfolio url"""
    return "https://portfolio.example.com"


class TestFreelancerProfileInitialization:
    """Test for Freelancer Profile creation"""

    def test_freelancer_profile_accepts_valid_requirements(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
        valid_portfolio_url: Optional[str],
    ):
        """
        Test that Freelancer profile is initialized with valid data

        Validates that:
        - Freelancer profile implements all the attributes required by Profile abstract base class
        - Freelancer profile implements all the attributes required by  FreelancerProfile class.
        """

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=valid_skills,
            portfolio_url=valid_portfolio_url,
        )

        assert freelancer_profile.user == valid_freelancer
        assert freelancer_profile.bio == valid_bio
        assert freelancer_profile.hourly_rate == valid_hourly_rate
        assert freelancer_profile.skills == valid_skills
        assert freelancer_profile.portfolio_url == valid_portfolio_url

        assert isinstance(freelancer_profile, FreelancerProfile)
        assert isinstance(freelancer_profile.hourly_rate, (int, float))
        assert isinstance(freelancer_profile.created_at, datetime)
        assert isinstance(freelancer_profile.profile_id, UUID)
        assert freelancer_profile.created_at.tzinfo is not None

    def test_freelancer_profile_accepts_none_portfolio_url(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
    ):
        """Test that Freelancer profile is initialized with declaring portfolio_url as None"""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=valid_skills,
            portfolio_url=None,
        )

        assert isinstance(freelancer_profile, FreelancerProfile)
        assert freelancer_profile.portfolio_url is None

    def test_freelancer_profile_is_initialized_without_portfolio_url(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
    ):
        """Test that Freelancer profile is initialized without declaring portfolio_url (its has None default value)"""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=valid_skills,
        )

        assert isinstance(freelancer_profile, FreelancerProfile)
        assert freelancer_profile.portfolio_url is None

    def test_freelancer_profile_raises_value_error_with_empty_portfolio_url(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
    ):
        """
        Test that Freelancer profile is not initialized with empty portfolio_url and raises ValueError
        This error occurs when portfolio_url is explicitly provided as an empty string.
        """

        with pytest.raises(ValueError, match="Portfolio URL cannot be empty"):
            FreelancerProfile(
                user=valid_freelancer,
                bio=valid_bio,
                hourly_rate=valid_hourly_rate,
                skills=valid_skills,
                portfolio_url="",
            )

    def test_freelancer_profile_raises_value_error_with_incorrect_portfolio_url(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
    ):
        """
        Test that Freelancer profile is not initialized with incorrect portfolio_url and raises ValueError
        This error occurs when portfolio_url is explicitly provided and starts with an incorrect url (does not start with http:// or https://)
        """

        with pytest.raises(
            ValueError, match="Portfolio URL must start with 'http://', 'https://'"
        ):
            FreelancerProfile(
                user=valid_freelancer,
                bio=valid_bio,
                hourly_rate=valid_hourly_rate,
                skills=valid_skills,
                portfolio_url="abc//invalid.portfolio.com",
            )

    def test_freelancer_profile_raises_value_error_with_negative_hourly_rate(
        self, valid_freelancer: Freelancer, valid_bio: str, valid_skills: list[str]
    ):
        """
        Test that Freelancer profile is not initialized and raises ValueError with negative hourly rate
        """

        with pytest.raises(ValueError, match="Hourly rate must be greater than zero"):
            FreelancerProfile(
                user=valid_freelancer,
                bio=valid_bio,
                hourly_rate=-10.5,
                skills=valid_skills,
            )

    def test_freelancer_profile_raises_value_error_with_hourly_rate_zero(
        self, valid_freelancer: Freelancer, valid_bio: str, valid_skills: list[str]
    ):
        """Test Freelancer profile is not initialized and raises ValueError with zero hourly rate."""
        with pytest.raises(ValueError, match="Hourly rate must be greater than zero"):
            FreelancerProfile(
                user=valid_freelancer,
                bio=valid_bio,
                hourly_rate=0,
                skills=valid_skills,
            )

    def test_freelancer_profile_raises_value_error_without_skills(
        self, valid_freelancer: Freelancer, valid_bio: str, valid_hourly_rate: float
    ):
        """
        Test that Freelancer profile is not initialized without skills and raises ValueError
        The error is raised in the method add skill
        """

        with pytest.raises(ValueError, match="Skill cannot be empty"):
            FreelancerProfile(
                user=valid_freelancer,
                bio=valid_bio,
                hourly_rate=valid_hourly_rate,
                skills=[""],
            )

    def test_freelancer_profile_setter_hourly_rate_raises_value_error_with_negative_rate(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_skills: list[str],
    ):
        """Test Freelancer profile is initialized correctly, but hourly_rate setter raises ValueError if try to set hourly_rate that is not greater than zero."""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=45.0,
            skills=valid_skills,
        )
        with pytest.raises(ValueError, match="Hourly rate must be greater than zero"):
            freelancer_profile.hourly_rate = -30.0

        assert freelancer_profile.hourly_rate == 45.0


class TestFreelancerProfileAddSkillValidation:
    """Test Freelancer profile method add_skill()"""

    def test_freelancer_profile_add_skill_with_valid_data(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
    ):
        """Test add_skill() with valid new skill."""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Python"],
        )

        freelancer_profile.add_skill("developer")

        assert len(freelancer_profile.skills) == 2
        assert freelancer_profile.skills == ["Python", "Developer"]

    def test_freelancer_profile_add_skill_ignores_duplicate_case_insensitive(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
    ):
        """Test that add_skill() should ignore duplicates (case-insensitive)."""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Python"],
        )

        freelancer_profile.add_skill("PYTHON")

        assert len(freelancer_profile.skills) == 1
        assert freelancer_profile.skills == ["Python"]


class TestFreelancerProfileDeleteSkillValidation:
    """Test Freelancer profile method delete_skill()"""

    def test_freelancer_profile_delete_skill_with_valid_data(
        self, valid_freelancer: Freelancer, valid_bio: str, valid_hourly_rate: float
    ):
        """Test delete_skill() with valid skills works with case-insensitive"""
        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Python", "Postgres"],
        )

        freelancer_profile.delete_skill("POSTGRES")

        assert len(freelancer_profile.skills) == 1
        assert freelancer_profile.skills == ["Python"]

    def test_freelancer_profile_delete_skill_raises_error_when_deleting_last_skill(
        self, valid_freelancer: Freelancer, valid_bio: str, valid_hourly_rate: float
    ):
        """Test that delete_skill() should raise error when attempting to delete last skill."""
        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Postgres"],
        )
        with pytest.raises(ValueError) as exc_info:
            freelancer_profile.delete_skill("POSTGRES")

        assert "Add a replacement skill before removing this one." in str(
            exc_info.value
        )
        assert len(freelancer_profile.skills) == 1
        assert freelancer_profile.skills == ["Postgres"]

    def test_freelancer_profile_delete_skill_idempotent_when_skill_not_exists(
        self, valid_freelancer, valid_bio, valid_hourly_rate
    ):
        """Test that delete_skill() should be idempotent when skill doesn't exist."""
        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Python", "Django"],
        )

        freelancer_profile.delete_skill("JavaScript")

        assert len(freelancer_profile.skills) == 2
        assert freelancer_profile.skills == ["Python", "Django"]


class TestFreelancerProfileDisplayInfo:
    """Test Freelancer profile implemented Profile abstract method display_info()"""

    def test_freelancer_profile_display_info_with_complete_valid_data(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_portfolio_url: str,
    ):
        """Test display_info() returns correctly formatted string with all fields include portfolio_url"""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=["Python", "Django", "Api Development"],
            portfolio_url=valid_portfolio_url,
        )
        result = freelancer_profile.display_info()

        assert "Freelance: user@test.com" in result
        assert "$50.00/hr" in result
        assert "Python, Django, Api Development" in result
        assert "Experienced Python developer looking for collaboration" in result
        assert "https://portfolio.example.com" in result

    def test_freelancer_profile_display_info_valid_data_without_profile_url(
        self,
        valid_freelancer: Freelancer,
        valid_bio: str,
        valid_hourly_rate: float,
        valid_skills: list[str],
    ):
        """Test display_info() returns correctly formatted string without portfolio_url"""

        freelancer_profile = FreelancerProfile(
            user=valid_freelancer,
            bio=valid_bio,
            hourly_rate=valid_hourly_rate,
            skills=valid_skills,
        )
        result = freelancer_profile.display_info()

        assert isinstance(result, str)
        assert "Freelance: user@test.com" in result
        assert "$50.00/hr" in result
        assert "Python" in result
        assert "Experienced Python developer looking for collaboration" in result
        assert "Portfolio" not in result


def test_freelancer_profile_inherits_from_profile_class():
    """Test that FreelancerProfile should be a subclass of Profile"""

    assert issubclass(FreelancerProfile, Profile)
