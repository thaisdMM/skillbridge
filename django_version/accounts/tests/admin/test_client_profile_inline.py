"""Tests for the profile section rendered inside the client account screen."""

import pytest
from django.contrib import admin as django_admin
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.admin import ClientAdmin, ClientProfileInline
from accounts.models.client import Client
from accounts.models.staff_user import StaffUser
from profiles.models.client_profile import ClientProfile
from profiles.models.skill import Skill


@pytest.fixture
def admin_request() -> HttpRequest:
    """Provide a GET request with an administrator attached for building the section."""
    factory = RequestFactory()
    request = factory.get("/")
    request.user = StaffUser(is_active=True, is_staff=True, is_superuser=True)
    return request


@pytest.fixture
def valid_profile_section_data() -> dict[str, str]:
    """Valid management form and field data for a filled client profile section."""
    return {
        "profile-TOTAL_FORMS": "1",
        "profile-INITIAL_FORMS": "0",
        "profile-MIN_NUM_FORMS": "0",
        "profile-MAX_NUM_FORMS": "1",
        "profile-0-company_name": "Client Company",
        "profile-0-max_budget": "500.00",
        "profile-0-website_url": "",
        "profile-0-bio": "Company looking for Python developer collaboration",
    }


@pytest.fixture
def untouched_profile_section_data(
    valid_profile_section_data: dict[str, str],
) -> dict[str, str]:
    """Section data exactly as rendered for an account that has no profile yet."""
    return {
        **valid_profile_section_data,
        "profile-0-company_name": "",
        "profile-0-max_budget": "",
        "profile-0-bio": "",
    }


def test_client_admin_attaches_the_client_profile_inline() -> None:
    """ClientAdmin renders the client profile section and no other inline."""
    assert ClientAdmin.inlines == (ClientProfileInline,)


def test_client_profile_inline_binds_to_the_client_profile_model() -> None:
    """The profile section edits ClientProfile."""
    assert ClientProfileInline.model is ClientProfile


def test_client_profile_inline_offers_one_blank_form_slot() -> None:
    """The section renders a blank slot so a profile can be started in place."""
    assert ClientProfileInline.extra == 1


def test_client_profile_inline_caps_the_section_at_one_profile() -> None:
    """The section never offers a way to add a second profile."""
    assert ClientProfileInline.max_num == 1


def test_client_profile_inline_renders_no_removal_checkbox() -> None:
    """The section offers no removal checkbox."""
    assert ClientProfileInline.can_delete is False


def test_client_profile_inline_refuses_delete_permission(
    admin_request: HttpRequest,
) -> None:
    """has_delete_permission returns False — a profile is never deleted from the section."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    assert inline_instance.has_delete_permission(admin_request) is False


def test_client_profile_inline_shows_the_timestamps_read_only() -> None:
    """The creation and update timestamps cannot be edited from the section."""
    assert ClientProfileInline.readonly_fields == ("created_at", "updated_at")


def test_client_profile_inline_groups_the_fields_as_contracted() -> None:
    """The section presents the four contracted field groups in the contracted order."""
    assert ClientProfileInline.fieldsets == (
        (
            None,
            {"fields": ("company_name", "max_budget", "website_url")},
        ),
        ("Interests", {"fields": ("interests",)}),
        ("Biography", {"fields": ("bio",)}),
        (
            "Important Dates",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


def test_client_profile_inline_selects_interests_through_a_two_column_widget() -> None:
    """Interests are attached and detached through the two-column selector."""
    assert ClientProfileInline.filter_horizontal == ("interests",)


@pytest.mark.django_db
def test_interests_widget_offers_no_add_related_control(
    admin_request: HttpRequest,
) -> None:
    """The interests widget carries no add-related control — vocabulary is created elsewhere."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formfield = inline_instance.formfield_for_dbfield(
        ClientProfile._meta.get_field("interests"), admin_request
    )

    assert formfield.widget.can_add_related is False


@pytest.mark.django_db
def test_rendered_interests_widget_carries_no_add_related_link(
    admin_request: HttpRequest,
) -> None:
    """The rendered interests widget contains no link opening the skill creation popup."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formfield = inline_instance.formfield_for_dbfield(
        ClientProfile._meta.get_field("interests"), admin_request
    )

    rendered = formfield.widget.render("interests", None)

    assert "add_id_interests" not in rendered


@pytest.mark.django_db
def test_section_offers_exactly_one_form_for_an_account_without_a_profile(
    admin_request: HttpRequest,
    client_user: Client,
) -> None:
    """An account with no profile gets exactly one form in its profile section."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=client_user)

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_section_form_is_blank_for_an_account_without_a_profile(
    admin_request: HttpRequest,
    client_user: Client,
) -> None:
    """The single form offered to an account with no profile is blank."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=client_user)

    assert formset.forms[0].instance.pk is None


@pytest.mark.django_db
def test_section_offers_exactly_one_form_for_an_account_with_a_profile(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
) -> None:
    """An account that has a profile gets no blank second form."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=client_profile.user)

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_section_form_holds_the_existing_profile(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
) -> None:
    """The single form offered to an account with a profile is populated with it."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=client_profile.user)

    assert formset.forms[0].instance.pk == client_profile.pk


@pytest.mark.django_db
def test_section_offers_exactly_one_form_on_the_add_screen(
    admin_request: HttpRequest,
) -> None:
    """The add-client screen offers a profile section before the account exists."""
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=Client())

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_untouched_section_reports_no_change(
    admin_request: HttpRequest,
    client_user: Client,
    untouched_profile_section_data: dict[str, str],
) -> None:
    """A profile section submitted exactly as rendered reports itself unchanged."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        untouched_profile_section_data, instance=client_user
    )

    assert formset.forms[0].has_changed() is False


@pytest.mark.django_db
def test_untouched_section_creates_no_profile(
    admin_request: HttpRequest,
    client_user: Client,
    untouched_profile_section_data: dict[str, str],
) -> None:
    """Saving an account without touching the profile section creates no profile."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        untouched_profile_section_data, instance=client_user
    )
    assert formset.is_valid()

    formset.save()

    assert ClientProfile.objects.count() == 0


@pytest.mark.django_db
def test_non_positive_max_budget_is_refused_on_the_max_budget_field(
    admin_request: HttpRequest,
    client_user: Client,
    valid_profile_section_data: dict[str, str],
) -> None:
    """A maximum budget of zero is refused with max_budget_not_positive on its own field."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-max_budget": "0"},
        instance=client_user,
    )

    assert not formset.is_valid()

    errors = formset.forms[0].errors.as_data()
    assert "max_budget" in errors
    assert errors["max_budget"][0].code == "max_budget_not_positive"


@pytest.mark.django_db
def test_filling_the_section_while_deactivating_the_account_is_refused(
    admin_request: HttpRequest,
    client_user: Client,
    valid_profile_section_data: dict[str, str],
) -> None:
    """A profile filled in while Active is unticked is refused against the status being saved."""
    client_user.is_active = False
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=client_user
    )

    assert not formset.is_valid()

    errors = formset.forms[0].errors.as_data()
    assert "__all__" in errors
    assert errors["__all__"][0].code == "profile_for_inactive_account"


@pytest.mark.django_db
def test_refusal_on_a_hidden_field_leaves_no_orphan_error(
    admin_request: HttpRequest,
    client_user: Client,
    valid_profile_section_data: dict[str, str],
) -> None:
    """No error stays attached to the hidden user field, where nothing would render it."""
    client_user.is_active = False
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=client_user
    )
    assert not formset.is_valid()

    assert "user" not in formset.forms[0].errors


@pytest.mark.django_db
def test_error_on_a_visible_field_stays_on_that_field(
    admin_request: HttpRequest,
    client_user: Client,
    valid_profile_section_data: dict[str, str],
) -> None:
    """An error on a field the section displays is not moved to the form level."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-max_budget": "0"},
        instance=client_user,
    )
    assert not formset.is_valid()

    assert "max_budget" in formset.forms[0].errors
    assert formset.forms[0].non_field_errors() == []


@pytest.mark.django_db
def test_filling_the_section_while_reactivating_the_account_is_accepted(
    admin_request: HttpRequest,
    valid_client_data: dict[str, str],
    valid_profile_section_data: dict[str, str],
) -> None:
    """A profile filled in while Active is ticked on a deactivated account is accepted."""
    deactivated_client = Client.objects.create_user(
        **{**valid_client_data, "is_active": False}
    )
    deactivated_client.is_active = True
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=deactivated_client
    )

    assert formset.is_valid()


@pytest.mark.django_db
def test_editing_a_profile_on_a_deactivated_account_is_accepted(
    admin_request: HttpRequest,
    client_profile: ClientProfile,
    valid_profile_section_data: dict[str, str],
) -> None:
    """An existing profile stays editable once its account has been deactivated."""
    account = client_profile.user
    Client.objects.filter(pk=account.pk).update(is_active=False)
    account.refresh_from_db()
    inline_instance = ClientProfileInline(Client, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        {
            **valid_profile_section_data,
            "profile-INITIAL_FORMS": "1",
            "profile-0-id": str(client_profile.pk),
            "profile-0-max_budget": "750.00",
        },
        instance=account,
    )

    assert formset.is_valid()


@pytest.mark.django_db
def test_saved_section_attaches_the_selected_interests(
    admin_request: HttpRequest,
    client_user: Client,
    valid_profile_section_data: dict[str, str],
    skill: Skill,
) -> None:
    """An interest selected in the section is attached to the profile the save creates."""
    inline_instance = ClientProfileInline(Client, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-interests": [str(skill.pk)]},
        instance=client_user,
    )
    assert formset.is_valid()

    formset.save()

    assert list(client_user.profile.interests.all()) == [skill]
