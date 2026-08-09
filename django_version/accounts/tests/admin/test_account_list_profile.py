"""Tests for the profile presence badge and profile filter on the account lists."""

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
from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile


@pytest.fixture
def admin_request() -> HttpRequest:
    """Provide a GET request for building a changelist queryset."""
    return RequestFactory().get("/")


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
    Client.objects.create_user(**{**valid_client_data, "email": "noprofile@example.com"})
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


def test_staff_user_admin_neither_defines_nor_inherits_profile_badge() -> None:
    """StaffUserAdmin shows no profile column — a staff account has no profile."""
    assert not hasattr(StaffUserAdmin, "profile_badge")


def test_staff_user_admin_offers_no_profile_filter() -> None:
    """StaffUserAdmin cannot be narrowed by profile presence."""
    assert HasProfileFilter not in StaffUserAdmin.list_filter
