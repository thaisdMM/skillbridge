"""Tests for the accounts admin actions and base/mixin composition."""

import pytest
from django.contrib import admin as django_admin
from django.contrib.messages import WARNING, get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.admin import ClientAdmin, FreelancerAdmin, StaffUserAdmin
from accounts.models.client import Client
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser


@pytest.fixture
def admin_request() -> HttpRequest:
    """Provide a GET request with message storage attached for admin action testing."""
    factory = RequestFactory()
    request = factory.get("/")
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


@pytest.mark.django_db
def test_set_unavailable_sets_all_selected_freelancers_to_unavailable(
    admin_request: HttpRequest,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """All selected freelancers end with is_available=False after set_unavailable."""
    available_freelancer_one = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "freelancer1@example.com"}
    )
    available_freelancer_two = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "freelancer2@example.com"}
    )
    queryset = Freelancer.objects.filter(
        pk__in=[available_freelancer_one.pk, available_freelancer_two.pk]
    )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    admin_instance.set_unavailable(admin_request, queryset)

    available_freelancer_one.refresh_from_db()
    available_freelancer_two.refresh_from_db()
    assert available_freelancer_one.is_available is False
    assert available_freelancer_two.is_available is False


@pytest.mark.django_db
def test_set_available_sets_active_freelancers_to_available(
    admin_request: HttpRequest,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Active freelancers become is_available=True after set_available."""
    active_freelancer_one = Freelancer.objects.create_user(
        **{
            **valid_freelancer_data,
            "email": "freelancer1@example.com",
            "is_available": False,
        }
    )
    active_freelancer_two = Freelancer.objects.create_user(
        **{
            **valid_freelancer_data,
            "email": "freelancer2@example.com",
            "is_available": False,
        }
    )
    queryset = Freelancer.objects.filter(
        pk__in=[active_freelancer_one.pk, active_freelancer_two.pk]
    )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    admin_instance.set_available(admin_request, queryset)

    active_freelancer_one.refresh_from_db()
    active_freelancer_two.refresh_from_db()
    assert active_freelancer_one.is_available is True
    assert active_freelancer_two.is_available is True


@pytest.mark.django_db
def test_set_available_skips_inactive_freelancer_and_does_not_persist_forbidden_state(
    admin_request: HttpRequest,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """An inactive freelancer is skipped by set_available — the forbidden state is never persisted."""
    inactive_freelancer = Freelancer.objects.create_user(
        **{
            **valid_freelancer_data,
            "email": "inactive@example.com",
            "is_active": False,
            "is_available": False,
        }
    )
    queryset = Freelancer.objects.filter(pk=inactive_freelancer.pk)
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    admin_instance.set_available(admin_request, queryset)

    inactive_freelancer.refresh_from_db()
    assert inactive_freelancer.is_available is False


@pytest.mark.django_db
def test_set_available_updates_active_and_skips_inactive_in_mixed_queryset(
    admin_request: HttpRequest,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Active freelancers are updated and the inactive one is skipped in a mixed queryset."""
    active_freelancer = Freelancer.objects.create_user(
        **{
            **valid_freelancer_data,
            "email": "active@example.com",
            "is_available": False,
        }
    )
    inactive_freelancer = Freelancer.objects.create_user(
        **{
            **valid_freelancer_data,
            "email": "inactive@example.com",
            "is_active": False,
            "is_available": False,
        }
    )
    queryset = Freelancer.objects.filter(
        pk__in=[active_freelancer.pk, inactive_freelancer.pk]
    )
    admin_instance = FreelancerAdmin(Freelancer, django_admin.site)

    admin_instance.set_available(admin_request, queryset)

    active_freelancer.refresh_from_db()
    inactive_freelancer.refresh_from_db()
    assert active_freelancer.is_available is True
    assert inactive_freelancer.is_available is False

    messages_sent = list(get_messages(admin_request))
    assert len(messages_sent) == 2
    assert sum(1 for message in messages_sent if message.level == WARNING) == 1


@pytest.mark.django_db
def test_activate_accounts_reactivates_account_through_base_admin(
    admin_request: HttpRequest,
    valid_client_data: dict[str, str],
) -> None:
    """activate_accounts, inherited from BaseAccountAdmin, sets is_active=True on the queryset."""
    inactive_client = Client.objects.create_user(
        **{**valid_client_data, "is_active": False}
    )
    queryset = Client.objects.filter(pk=inactive_client.pk)
    admin_instance = ClientAdmin(Client, django_admin.site)

    admin_instance.activate_accounts(admin_request, queryset)

    inactive_client.refresh_from_db()
    assert inactive_client.is_active is True


@pytest.mark.django_db
def test_deactivate_accounts_deactivates_account_through_staff_user_admin(
    admin_request: HttpRequest,
    valid_user_data: dict[str, str],
) -> None:
    """deactivate_accounts, defined on StaffUserAdmin, sets is_active=False on the queryset."""
    active_staff_user = StaffUser.objects.create_user(**valid_user_data)
    queryset = StaffUser.objects.filter(pk=active_staff_user.pk)
    admin_instance = StaffUserAdmin(StaffUser, django_admin.site)

    admin_instance.deactivate_accounts(admin_request, queryset)

    active_staff_user.refresh_from_db()
    assert active_staff_user.is_active is False


def test_freelancer_admin_neither_defines_nor_inherits_deactivate_accounts() -> None:
    """FreelancerAdmin must not expose bulk deactivation, preserving its individual-only removal."""
    assert "deactivate_accounts" not in FreelancerAdmin.actions
    assert not hasattr(FreelancerAdmin, "deactivate_accounts")


def test_client_admin_neither_defines_nor_inherits_deactivate_accounts() -> None:
    """ClientAdmin must not expose bulk deactivation, preserving its individual-only removal."""
    assert "deactivate_accounts" not in ClientAdmin.actions
    assert not hasattr(ClientAdmin, "deactivate_accounts")
