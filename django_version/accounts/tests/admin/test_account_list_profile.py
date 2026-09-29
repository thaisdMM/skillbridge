"""
Tests for the profile columns and filters on the account lists.

Covers the profile presence badge, the profile presence filter, and the skill
filter each list offers.

The skill filter is measured through a whole changelist rather than through the
filter alone: an account is listed once however many skills its profile holds,
and the queryset that guarantees it is built by the changelist, not by any
filter object.
"""

import pytest
from django.contrib import admin as django_admin
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.admin import (
    ClientAdmin,
    FreelancerAdmin,
    HasProfileFilter,
    StaffUserAdmin,
)
from accounts.models.client import Client
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser
from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


@pytest.fixture
def admin_request() -> HttpRequest:
    """Provide a GET request for building a changelist queryset."""
    return RequestFactory().get("/")


@pytest.fixture
def administrator() -> StaffUser:
    """Provide an administrator to attach to a request that builds a changelist."""
    return StaffUser(is_active=True, is_staff=True, is_superuser=True)


@pytest.mark.django_db
def test_profile_badge_reports_a_freelancer_that_has_a_profile(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
) -> None:
    """The badge is green and reads Yes for a freelancer whose profile exists."""
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    account = admin_instance.get_queryset(admin_request).get(
        pk=freelancer_profile.user_id
    )
    badge = admin_instance.profile_badge(account)

    assert "green" in badge
    assert "Yes" in badge


@pytest.mark.django_db
def test_profile_badge_reports_a_freelancer_that_has_no_profile(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
) -> None:
    """The badge is red and reads No for a freelancer with no profile."""
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    account = admin_instance.get_queryset(admin_request).get(pk=freelancer_user.pk)
    badge = admin_instance.profile_badge(account)

    assert "red" in badge
    assert "No" in badge


@pytest.mark.django_db
def test_profile_badge_reports_a_client_that_has_a_profile(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
) -> None:
    """The badge is green and reads Yes for a client whose profile exists."""
    admin_instance = ClientAdmin(Client, django_admin.site)

    account = admin_instance.get_queryset(admin_request).get(pk=client_profile.user_id)
    badge = admin_instance.profile_badge(account)

    assert "green" in badge
    assert "Yes" in badge


@pytest.mark.django_db
def test_profile_badge_reports_a_client_that_has_no_profile(
    admin_request: HttpRequest,
    client_user: Client,
) -> None:
    """The badge is red and reads No for a client with no profile."""
    admin_instance = ClientAdmin(Client, django_admin.site)

    account = admin_instance.get_queryset(admin_request).get(pk=client_user.pk)
    badge = admin_instance.profile_badge(account)

    assert "red" in badge
    assert "No" in badge


@pytest.mark.django_db
def test_profile_filter_narrows_the_freelancer_list_to_accounts_without_a_profile(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Selecting "without a profile" lists exactly the freelancers that have none."""
    freelancer_without_profile = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "noprofile@example.com"}
    )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)
    profile_filter = HasProfileFilter(
        admin_request, {"has_profile": ["no"]}, Freelancer, admin_instance
    )

    filtered = profile_filter.queryset(admin_request, Freelancer.objects.all())

    assert list(filtered) == [freelancer_without_profile]


@pytest.mark.django_db
def test_profile_filter_narrows_the_freelancer_list_to_accounts_with_a_profile(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Selecting "with a profile" lists exactly the freelancers that have one."""
    Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "noprofile@example.com"}
    )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)
    profile_filter = HasProfileFilter(
        admin_request, {"has_profile": ["yes"]}, Freelancer, admin_instance
    )

    filtered = profile_filter.queryset(admin_request, Freelancer.objects.all())

    assert list(filtered) == [freelancer_profile.user]


@pytest.mark.django_db
def test_profile_filter_narrows_the_client_list_to_accounts_without_a_profile(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
    valid_client_data: dict[str, str],
) -> None:
    """Selecting "without a profile" lists exactly the clients that have none."""
    client_without_profile = Client.objects.create_user(
        **{**valid_client_data, "email": "noprofile@example.com"}
    )
    admin_instance = ClientAdmin(Client, django_admin.site)
    profile_filter = HasProfileFilter(
        admin_request, {"has_profile": ["no"]}, Client, admin_instance
    )

    filtered = profile_filter.queryset(admin_request, Client.objects.all())

    assert list(filtered) == [client_without_profile]


@pytest.mark.django_db
def test_profile_filter_narrows_the_client_list_to_accounts_with_a_profile(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
    valid_client_data: dict[str, str],
) -> None:
    """Selecting "with a profile" lists exactly the clients that have one."""
    Client.objects.create_user(
        **{**valid_client_data, "email": "noprofile@example.com"}
    )
    admin_instance = ClientAdmin(Client, django_admin.site)
    profile_filter = HasProfileFilter(
        admin_request, {"has_profile": ["yes"]}, Client, admin_instance
    )

    filtered = profile_filter.queryset(admin_request, Client.objects.all())

    assert list(filtered) == [client_profile.user]


@pytest.mark.django_db
def test_profile_badge_costs_no_query_per_row(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
    valid_freelancer_data: dict[str, str | bool],
    django_assert_num_queries,
) -> None:
    """A page of freelancers resolves every badge in the single changelist query."""
    for index in range(4):
        Freelancer.objects.create_user(
            **{**valid_freelancer_data, "email": f"freelancer{index}@example.com"}
        )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    with django_assert_num_queries(1):
        for account in admin_instance.get_queryset(admin_request):
            admin_instance.profile_badge(account)


@pytest.mark.django_db
def test_the_skill_filter_lists_only_the_freelancers_offering_that_skill(
    administrator: StaffUser,
    freelancer_profile: FreelancerProfile,
    skill: Skill,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Filtering the freelancer list by a skill lists exactly the freelancers offering it."""
    freelancer_profile.skills.add(skill)
    account_without_the_skill = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "other@example.com"}
    )
    FreelancerProfile.objects.create(user=account_without_the_skill)
    request = RequestFactory().get("/", {"profile__skills__id__exact": str(skill.pk)})
    request.user = administrator
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)

    assert list(changelist.queryset) == [freelancer_profile.user]


@pytest.mark.django_db
def test_the_skill_filter_lists_only_the_clients_holding_that_interest(
    administrator: StaffUser,
    client_profile: ClientProfile,
    skill: Skill,
    valid_client_data: dict[str, str],
) -> None:
    """Filtering the client list by a skill lists exactly the clients holding it as an interest."""
    client_profile.interests.add(skill)
    account_without_the_interest = Client.objects.create_user(
        **{**valid_client_data, "email": "other@example.com"}
    )
    ClientProfile.objects.create(user=account_without_the_interest)
    request = RequestFactory().get(
        "/", {"profile__interests__id__exact": str(skill.pk)}
    )
    request.user = administrator
    admin_instance = ClientAdmin(Client, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)

    assert list(changelist.queryset) == [client_profile.user]


@pytest.mark.django_db
def test_a_freelancer_offering_several_skills_is_listed_once_by_the_skill_filter(
    administrator: StaffUser,
    freelancer_profile: FreelancerProfile,
    skill: Skill,
) -> None:
    """A profile holding several skills places its account on the filtered list exactly once."""
    freelancer_profile.skills.add(skill)
    freelancer_profile.skills.add(
        Skill.objects.create(name="Django", category=Skill.Category.TECHNOLOGY)
    )
    freelancer_profile.skills.add(
        Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    )
    request = RequestFactory().get("/", {"profile__skills__id__exact": str(skill.pk)})
    request.user = administrator
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)

    assert list(changelist.queryset) == [freelancer_profile.user]


@pytest.mark.django_db
def test_the_skill_filter_lists_nothing_for_a_skill_no_profile_offers(
    administrator: StaffUser,
    freelancer_profile: FreelancerProfile,
    skill: Skill,
) -> None:
    """Filtering by a skill no profile refers to empties the list and raises nothing."""
    request = RequestFactory().get("/", {"profile__skills__id__exact": str(skill.pk)})
    request.user = administrator
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)

    assert list(changelist.queryset) == []


@pytest.mark.django_db
def test_the_freelancer_skill_filter_offers_only_the_skills_a_profile_offers(
    administrator: StaffUser,
    freelancer_profile: FreelancerProfile,
    skill: Skill,
) -> None:
    """The freelancer skill filter lists the skills in use, not the whole vocabulary."""
    freelancer_profile.skills.add(skill)
    Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    request = RequestFactory().get("/")
    request.user = administrator
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)
    skill_filter = next(
        spec
        for spec in changelist.filter_specs
        if isinstance(spec, django_admin.RelatedOnlyFieldListFilter)
    )

    assert [label for _, label in skill_filter.lookup_choices] == ["Python"]


@pytest.mark.django_db
def test_the_client_skill_filter_offers_only_the_skills_a_profile_holds(
    administrator: StaffUser,
    client_profile: ClientProfile,
    skill: Skill,
) -> None:
    """The client interest filter lists the interests in use, not the whole vocabulary."""
    client_profile.interests.add(skill)
    Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    request = RequestFactory().get("/")
    request.user = administrator
    admin_instance = ClientAdmin(Client, django_admin.site)

    changelist = admin_instance.get_changelist_instance(request)
    interest_filter = next(
        spec
        for spec in changelist.filter_specs
        if isinstance(spec, django_admin.RelatedOnlyFieldListFilter)
    )

    assert [label for _, label in interest_filter.lookup_choices] == ["Python"]


def test_staff_user_admin_neither_defines_nor_inherits_profile_badge() -> None:
    """StaffUserAdmin shows no profile column — a staff account has no profile."""
    assert not hasattr(StaffUserAdmin, "profile_badge")


def test_staff_user_admin_offers_no_profile_filter() -> None:
    """StaffUserAdmin cannot be narrowed by profile presence."""
    assert HasProfileFilter not in StaffUserAdmin.list_filter


def test_staff_user_admin_offers_no_skill_filter() -> None:
    """StaffUserAdmin cannot be narrowed by skill — a staff account has no profile to read one from."""
    assert not [
        entry for entry in StaffUserAdmin.list_filter if "profile" in str(entry)
    ]
