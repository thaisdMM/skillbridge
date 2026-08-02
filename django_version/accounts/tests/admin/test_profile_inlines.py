"""Tests for the profile sections rendered inside the account screens."""

import pytest
from django.contrib import admin as django_admin
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.admin import FreelancerAdmin, FreelancerProfileInline
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser
from profiles.models.freelancer_profile import FreelancerProfile
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
    """Valid management form and field data for a filled freelancer profile section."""
    return {
        "profile-TOTAL_FORMS": "1",
        "profile-INITIAL_FORMS": "0",
        "profile-MIN_NUM_FORMS": "0",
        "profile-MAX_NUM_FORMS": "1",
        "profile-0-hourly_rate": "50.00",
        "profile-0-years_of_experience": "5",
        "profile-0-portfolio_url": "",
        "profile-0-bio": "Experienced Python developer looking for collaboration",
    }


@pytest.fixture
def untouched_profile_section_data(
    valid_profile_section_data: dict[str, str],
) -> dict[str, str]:
    """Section data exactly as rendered for an account that has no profile yet."""
    return {
        **valid_profile_section_data,
        "profile-0-hourly_rate": "",
        "profile-0-years_of_experience": "0",
        "profile-0-bio": "",
    }


def test_freelancer_admin_attaches_the_freelancer_profile_inline() -> None:
    """FreelancerAdmin renders the freelancer profile section and no other inline."""
    assert FreelancerAdmin.inlines == (FreelancerProfileInline,)


def test_freelancer_profile_inline_binds_to_the_freelancer_profile_model() -> None:
    """The profile section edits FreelancerProfile."""
    assert FreelancerProfileInline.model is FreelancerProfile


def test_freelancer_profile_inline_offers_one_blank_form_slot() -> None:
    """The section renders a blank slot so a profile can be started in place."""
    assert FreelancerProfileInline.extra == 1


def test_freelancer_profile_inline_caps_the_section_at_one_profile() -> None:
    """The section never offers a way to add a second profile."""
    assert FreelancerProfileInline.max_num == 1


def test_freelancer_profile_inline_renders_no_removal_checkbox() -> None:
    """The section offers no removal checkbox."""
    assert FreelancerProfileInline.can_delete is False


def test_freelancer_profile_inline_refuses_delete_permission(
    admin_request: HttpRequest,
) -> None:
    """has_delete_permission returns False — a profile is never deleted from the section."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    assert inline_instance.has_delete_permission(admin_request) is False


def test_freelancer_profile_inline_shows_the_timestamps_read_only() -> None:
    """The creation and update timestamps cannot be edited from the section."""
    assert FreelancerProfileInline.readonly_fields == ("created_at", "updated_at")


def test_freelancer_profile_inline_groups_the_fields_as_contracted() -> None:
    """The section presents the four contracted field groups in the contracted order."""
    assert FreelancerProfileInline.fieldsets == (
        (
            None,
            {"fields": ("hourly_rate", "years_of_experience", "portfolio_url")},
        ),
        ("Skills", {"fields": ("skills",)}),
        ("Biography", {"fields": ("bio",)}),
        (
            "Important Dates",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


def test_freelancer_profile_inline_selects_skills_through_a_two_column_widget() -> None:
    """Skills are attached and detached through the two-column selector."""
    assert FreelancerProfileInline.filter_horizontal == ("skills",)


@pytest.mark.django_db
def test_skills_widget_offers_no_add_related_control(
    admin_request: HttpRequest,
) -> None:
    """The skills widget carries no add-related control — vocabulary is created elsewhere."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formfield = inline_instance.formfield_for_dbfield(
        FreelancerProfile._meta.get_field("skills"), admin_request
    )

    assert formfield.widget.can_add_related is False


@pytest.mark.django_db
def test_rendered_skills_widget_carries_no_add_related_link(
    admin_request: HttpRequest,
) -> None:
    """The rendered skills widget contains no link opening the skill creation popup."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formfield = inline_instance.formfield_for_dbfield(
        FreelancerProfile._meta.get_field("skills"), admin_request
    )

    rendered = formfield.widget.render("skills", None)

    assert "add_id_skills" not in rendered


@pytest.mark.django_db
def test_section_offers_exactly_one_form_for_an_account_without_a_profile(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
) -> None:
    """An account with no profile gets exactly one form in its profile section."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=freelancer_user)

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_section_form_is_blank_for_an_account_without_a_profile(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
) -> None:
    """The single form offered to an account with no profile is blank."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=freelancer_user)

    assert formset.forms[0].instance.pk is None


@pytest.mark.django_db
def test_section_offers_exactly_one_form_for_an_account_with_a_profile(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
) -> None:
    """An account that has a profile gets no blank second form."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        instance=freelancer_profile.user
    )

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_section_form_holds_the_existing_profile(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
) -> None:
    """The single form offered to an account with a profile is populated with it."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        instance=freelancer_profile.user
    )

    assert formset.forms[0].instance.pk == freelancer_profile.pk


@pytest.mark.django_db
def test_section_offers_exactly_one_form_on_the_add_screen(
    admin_request: HttpRequest,
) -> None:
    """The add-freelancer screen offers a profile section before the account exists."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(instance=Freelancer())

    assert len(formset.forms) == 1


@pytest.mark.django_db
def test_untouched_section_reports_no_change(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    untouched_profile_section_data: dict[str, str],
) -> None:
    """A profile section submitted exactly as rendered reports itself unchanged."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        untouched_profile_section_data, instance=freelancer_user
    )

    assert formset.forms[0].has_changed() is False


@pytest.mark.django_db
def test_untouched_section_creates_no_profile(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    untouched_profile_section_data: dict[str, str],
) -> None:
    """Saving an account without touching the profile section creates no profile."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        untouched_profile_section_data, instance=freelancer_user
    )
    assert formset.is_valid()

    formset.save()

    assert FreelancerProfile.objects.count() == 0


@pytest.mark.django_db
def test_non_positive_hourly_rate_is_refused_on_the_hourly_rate_field(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """An hourly rate of zero is refused with hourly_rate_not_positive on its own field."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-hourly_rate": "0"},
        instance=freelancer_user,
    )

    assert not formset.is_valid()

    errors = formset.forms[0].errors.as_data()
    assert "hourly_rate" in errors
    assert errors["hourly_rate"][0].code == "hourly_rate_not_positive"


@pytest.mark.django_db
def test_biography_over_the_limit_is_refused_on_the_bio_field(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """A 501-character biography is refused with max_length on the bio field."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-bio": "x" * 501},
        instance=freelancer_user,
    )

    assert not formset.is_valid()

    errors = formset.forms[0].errors.as_data()
    assert "bio" in errors
    assert errors["bio"][0].code == "max_length"


@pytest.mark.django_db
def test_filling_the_section_while_deactivating_the_account_is_refused(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """A profile filled in while Active is unticked is refused against the status being saved."""
    freelancer_user.is_active = False
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=freelancer_user
    )

    assert not formset.is_valid()

    errors = formset.forms[0].errors.as_data()
    assert "__all__" in errors
    assert errors["__all__"][0].code == "profile_for_inactive_account"


@pytest.mark.django_db
def test_refusal_on_a_hidden_field_is_shown_above_the_section(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """The FR-029 refusal reaches non_field_errors, which the section renders."""
    freelancer_user.is_active = False
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=freelancer_user
    )
    assert not formset.is_valid()

    non_field_errors = formset.forms[0].non_field_errors().as_data()

    assert [error.code for error in non_field_errors] == [
        "profile_for_inactive_account"
    ]


@pytest.mark.django_db
def test_refusal_on_a_hidden_field_leaves_no_orphan_error(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """No error stays attached to the hidden user field, where nothing would render it."""
    freelancer_user.is_active = False
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=freelancer_user
    )
    assert not formset.is_valid()

    assert "user" not in formset.forms[0].errors


@pytest.mark.django_db
def test_error_on_a_visible_field_stays_on_that_field(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
) -> None:
    """An error on a field the section displays is not moved to the form level."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-hourly_rate": "0"},
        instance=freelancer_user,
    )
    assert not formset.is_valid()

    assert "hourly_rate" in formset.forms[0].errors
    assert formset.forms[0].non_field_errors() == []


@pytest.mark.django_db
def test_filling_the_section_while_reactivating_the_account_is_accepted(
    admin_request: HttpRequest,
    valid_freelancer_data: dict[str, str | bool],
    valid_profile_section_data: dict[str, str],
) -> None:
    """A profile filled in while Active is ticked on a deactivated account is accepted."""
    deactivated_freelancer = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "is_active": False, "is_available": False}
    )
    deactivated_freelancer.is_active = True
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        valid_profile_section_data, instance=deactivated_freelancer
    )

    assert formset.is_valid()


@pytest.mark.django_db
def test_editing_a_profile_on_a_deactivated_account_is_accepted(
    admin_request: HttpRequest,
    freelancer_profile: FreelancerProfile,
    valid_profile_section_data: dict[str, str],
) -> None:
    """An existing profile stays editable once its account has been deactivated."""
    account = freelancer_profile.user
    Freelancer.objects.filter(pk=account.pk).update(is_active=False, is_available=False)
    account.refresh_from_db()
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)

    formset = inline_instance.get_formset(admin_request)(
        {
            **valid_profile_section_data,
            "profile-INITIAL_FORMS": "1",
            "profile-0-id": str(freelancer_profile.pk),
            "profile-0-hourly_rate": "75.00",
        },
        instance=account,
    )

    assert formset.is_valid()


@pytest.mark.django_db
def test_saved_section_attaches_the_selected_skills(
    admin_request: HttpRequest,
    freelancer_user: Freelancer,
    valid_profile_section_data: dict[str, str],
    skill: Skill,
) -> None:
    """A skill selected in the section is attached to the profile the save creates."""
    inline_instance = FreelancerProfileInline(Freelancer, django_admin.site)
    formset = inline_instance.get_formset(admin_request)(
        {**valid_profile_section_data, "profile-0-skills": [str(skill.pk)]},
        instance=freelancer_user,
    )
    assert formset.is_valid()

    formset.save()

    assert list(freelancer_user.profile.skills.all()) == [skill]
