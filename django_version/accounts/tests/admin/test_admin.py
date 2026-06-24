"""Tests for FreelancerAdmin bulk availability actions."""

import pytest
from django.contrib import admin as django_admin
from django.contrib.messages import WARNING, get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.admin import FreelancerAdmin
from accounts.models.freelancer import Freelancer


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
