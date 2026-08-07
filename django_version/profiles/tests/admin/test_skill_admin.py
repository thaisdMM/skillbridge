"""Tests for the SkillAdmin screen configuration and its removal refusal."""

import pytest
from django.contrib import admin as django_admin
from django.contrib.admin.actions import delete_selected
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpRequest
from django.test import RequestFactory

from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser
from profiles.admin import SkillAdmin
from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


@pytest.fixture
def admin_user() -> StaffUser:
    """Provide an unsaved active superuser to act as the requesting administrator."""
    return StaffUser(is_active=True, is_staff=True, is_superuser=True)


@pytest.fixture
def admin_request(admin_user: StaffUser) -> HttpRequest:
    """Provide a GET request with an administrator and message storage attached."""
    factory = RequestFactory()
    request = factory.get("/")
    request.user = admin_user
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


@pytest.fixture
def confirmed_delete_request(admin_user: StaffUser) -> HttpRequest:
    """Provide a POST request carrying the delete confirmation the bulk action expects."""
    factory = RequestFactory()
    request = factory.post("/", {"post": "yes"})
    request.user = admin_user
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


@pytest.mark.parametrize(
    ("attribute", "expected"),
    [
        ("list_display", ("name", "category")),
        ("list_display_links", ("name",)),
        ("list_filter", ("category",)),
        ("search_fields", ("name",)),
        ("ordering", ("category", "name")),
        ("list_per_page", 25),
    ],
)
def test_skill_admin_declares_the_configured_screen_attribute(
    attribute: str,
    expected: tuple[str, ...] | int,
) -> None:
    """Each configured SkillAdmin screen attribute holds its contracted value."""
    assert getattr(SkillAdmin, attribute) == expected


def test_skill_admin_groups_name_and_category_in_one_unnamed_fieldset() -> None:
    """SkillAdmin presents name and category in a single unnamed fieldset."""
    assert SkillAdmin.fieldsets == ((None, {"fields": ("name", "category")}),)


def test_skill_admin_permits_deletion(admin_request: HttpRequest) -> None:
    """has_delete_permission returns True — a skill may be removed permanently."""
    admin_instance = SkillAdmin(Skill, django_admin.site)

    assert admin_instance.has_delete_permission(admin_request) is True


@pytest.mark.django_db
def test_get_deleted_objects_protects_nothing_for_a_skill_no_profile_refers_to(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """An unused skill is reported with an empty protected collection."""
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects([skill], admin_request)

    assert protected == []


@pytest.mark.django_db
def test_get_deleted_objects_protects_a_skill_a_freelancer_profile_refers_to(
    admin_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
) -> None:
    """A skill listed on a freelancer profile is reported as protected."""
    freelancer_profile.skills.add(skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects([skill], admin_request)

    assert protected != []


@pytest.mark.django_db
def test_get_deleted_objects_protects_a_skill_a_client_profile_refers_to(
    admin_request: HttpRequest,
    skill: Skill,
    client_profile: ClientProfile,
) -> None:
    """A skill listed as a client interest is reported as protected."""
    client_profile.interests.add(skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects([skill], admin_request)

    assert protected != []


@pytest.mark.django_db
def test_get_deleted_objects_summarizes_several_referring_profiles_in_one_entry(
    admin_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
    client_profile: ClientProfile,
    valid_freelancer_data: dict[str, str | bool],
) -> None:
    """Three referring profiles produce one protected entry carrying the count of three."""
    second_freelancer = Freelancer.objects.create_user(
        **{**valid_freelancer_data, "email": "second@example.com"}
    )
    second_profile = FreelancerProfile.objects.create(user=second_freelancer)
    freelancer_profile.skills.add(skill)
    second_profile.skills.add(skill)
    client_profile.interests.add(skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects([skill], admin_request)

    assert len(protected) == 1
    assert "3" in protected[0]


@pytest.mark.django_db
def test_get_deleted_objects_counts_a_profile_referring_to_several_selected_skills_once(
    admin_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
) -> None:
    """Three selected skills on one single profile produce a count of one."""
    second_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )
    third_skill = Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    freelancer_profile.skills.add(skill, second_skill, third_skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects(
        [skill, second_skill, third_skill], admin_request
    )

    assert len(protected) == 1
    assert "1" in protected[0]


@pytest.mark.django_db
def test_get_deleted_objects_counts_a_client_profile_referring_to_several_selected_skills_once(
    admin_request: HttpRequest,
    skill: Skill,
    client_profile: ClientProfile,
) -> None:
    """Three selected skills on one single client profile produce a count of one."""
    second_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )
    third_skill = Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    client_profile.interests.add(skill, second_skill, third_skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects(
        [skill, second_skill, third_skill], admin_request
    )

    assert len(protected) == 1
    assert "1" in protected[0]


@pytest.mark.django_db
def test_counting_referring_profiles_issues_two_queries_for_a_selection_of_three_skills(
    django_assert_num_queries,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
) -> None:
    """Counting the profiles referring to three selected skills issues two queries."""
    second_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )
    third_skill = Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    freelancer_profile.skills.add(skill, second_skill, third_skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)

    with django_assert_num_queries(2):
        admin_instance._count_referring_profiles([skill, second_skill, third_skill])


@pytest.mark.django_db
def test_refused_deletion_leaves_the_skill_attached_to_every_profile(
    confirmed_delete_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
    client_profile: ClientProfile,
) -> None:
    """A refused deletion detaches the skill from no profile and removes no join row."""
    freelancer_profile.skills.add(skill)
    client_profile.interests.add(skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)
    queryset = Skill.objects.filter(pk=skill.pk)

    delete_selected(admin_instance, confirmed_delete_request, queryset)

    assert list(freelancer_profile.skills.all()) == [skill]
    assert list(client_profile.interests.all()) == [skill]
    assert FreelancerProfile.skills.through.objects.count() == 1
    assert ClientProfile.interests.through.objects.count() == 1


@pytest.mark.django_db
def test_delete_selected_deletes_no_skill_when_one_of_the_selected_skills_is_in_use(
    confirmed_delete_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
) -> None:
    """A selection mixing an in-use skill with an unused one deletes neither."""
    unused_skill = Skill.objects.create(name="Figma", category=Skill.Category.DESIGN)
    freelancer_profile.skills.add(skill)
    admin_instance = SkillAdmin(Skill, django_admin.site)
    queryset = Skill.objects.filter(pk__in=[skill.pk, unused_skill.pk])

    delete_selected(admin_instance, confirmed_delete_request, queryset)

    assert Skill.objects.filter(pk=skill.pk).exists()
    assert Skill.objects.filter(pk=unused_skill.pk).exists()


@pytest.mark.django_db
def test_get_deleted_objects_protects_a_skill_referred_to_from_a_deactivated_account(
    admin_request: HttpRequest,
    skill: Skill,
    freelancer_profile: FreelancerProfile,
) -> None:
    """A skill referred to only by a profile on a deactivated account is still protected."""
    freelancer_profile.skills.add(skill)
    Freelancer.objects.filter(pk=freelancer_profile.user_id).update(
        is_active=False, is_available=False
    )
    admin_instance = SkillAdmin(Skill, django_admin.site)

    *_, protected = admin_instance.get_deleted_objects([skill], admin_request)

    assert protected != []


@pytest.mark.django_db
def test_add_form_refuses_a_name_an_existing_skill_already_carries(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """Adding a skill under a name already in the vocabulary is refused on the name field."""
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request)(
        {"name": "Python", "category": Skill.Category.TECHNOLOGY}
    )

    assert not form.is_valid()

    errors = form.errors.as_data()
    assert "name" in errors
    assert errors["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_add_form_refuses_a_case_variant_without_rewriting_the_stored_name(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """A name differing only in case is refused and the stored skill keeps its own spelling."""
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request)(
        {"name": "python", "category": Skill.Category.TECHNOLOGY}
    )

    assert not form.is_valid()

    errors = form.errors.as_data()
    assert "name" in errors
    assert errors["name"][0].code == "skill_name_duplicate"
    assert Skill.objects.get(pk=skill.pk).name == "Python"


@pytest.mark.django_db
def test_add_form_refuses_a_case_variant_padded_with_whitespace(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """A padded case variant of an existing name is refused on the name field."""
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request)(
        {"name": "  python  ", "category": Skill.Category.TECHNOLOGY}
    )

    assert not form.is_valid()

    errors = form.errors.as_data()
    assert "name" in errors
    assert errors["name"][0].code == "skill_name_duplicate"


@pytest.mark.django_db
def test_add_form_reports_the_required_and_the_empty_name_codes_for_a_blank_name(
    admin_request: HttpRequest,
) -> None:
    """A whitespace-only name is refused with both the required and the empty-name codes."""
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request)(
        {"name": "   ", "category": Skill.Category.TECHNOLOGY}
    )

    assert not form.is_valid()

    errors = form.errors.as_data()
    assert "name" in errors
    assert {error.code for error in errors["name"]} == {"required", "skill_name_empty"}


@pytest.mark.django_db
def test_add_form_accepts_a_name_no_skill_carries(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """A name no existing skill carries is accepted, so the rule refuses duplicates only."""
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request)(
        {"name": "Django", "category": Skill.Category.TECHNOLOGY}
    )

    assert form.is_valid()


@pytest.mark.django_db
def test_change_form_refuses_renaming_a_skill_onto_another_saved_skill_name(
    admin_request: HttpRequest,
    skill: Skill,
) -> None:
    """Renaming a saved skill onto another saved skill's name is refused on the change form."""
    renamed_skill = Skill.objects.create(
        name="Django", category=Skill.Category.TECHNOLOGY
    )
    admin_instance = SkillAdmin(Skill, django_admin.site)
    form = admin_instance.get_form(admin_request, obj=renamed_skill)(
        {"name": "python", "category": Skill.Category.TECHNOLOGY},
        instance=renamed_skill,
    )

    assert not form.is_valid()

    errors = form.errors.as_data()
    assert "name" in errors
    assert errors["name"][0].code == "skill_name_duplicate"
