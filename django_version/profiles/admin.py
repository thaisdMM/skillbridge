"""
Django admin configuration for the profiles app.

Registers the Skill model with a customized interface including list_display,
search, category filter, and fieldset grouping.

Skill is the only profiles model registered here. Freelancer and client
profiles are administered inside the account screen they belong to, so their
inlines live in accounts/admin.py.
"""

from collections.abc import Sequence

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.translation import ngettext

from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile
from profiles.models.skill import Skill


@admin.register(Skill)
class SkillAdmin(admin.ModelAdmin):
    """
    Admin interface for the Skill model.

    Provides list display with name and category, search by name, filtering by
    category, and fieldset grouping on the add and change forms.

    Deletion is enabled: a skill may be removed permanently while no profile
    refers to it. Removal is refused once any freelancer or client profile
    does.
    """

    list_display = ("name", "category")
    list_display_links = ("name",)
    list_filter = ("category",)
    search_fields = ("name",)
    ordering = ("category", "name")
    list_per_page = 25

    fieldsets = (
        (
            None,
            {
                "fields": ("name", "category"),
            },
        ),
    )

    def get_deleted_objects(
        self, objs: QuerySet[Skill] | Sequence[Skill], request: HttpRequest
    ) -> tuple[list, dict, set, list]:
        """
        Mark the selected skills as protected while profiles still refer to them.

        Counts the distinct freelancer and client profiles referring to the
        selection. When the count is greater than zero, a single summary line
        carrying it is added to the protected collection, which stops the
        deletion on both the delete view and the delete selected action.

        Args:
            objs: The skills selected for removal.
            request: The current admin request.

        Returns:
            tuple: The deletable objects, the per-model counts, the
                permissions needed, and the protected collection.
        """
        deletable_objects, model_count, perms_needed, protected = (
            super().get_deleted_objects(objs, request)
        )

        referring_profiles = self._count_referring_profiles(objs)

        if referring_profiles:
            protected = list(protected) + [self._in_use_summary(referring_profiles)]

        return deletable_objects, model_count, perms_needed, protected

    @staticmethod
    def _count_referring_profiles(objs: QuerySet[Skill] | Sequence[Skill]) -> int:
        """
        Count the distinct profiles referring to any of the selected skills.

        Counts freelancer profiles and client profiles separately, one
        aggregate query each, and returns the two totals added together. A
        profile referring to several of the selected skills counts once.

        Args:
            objs: The skills selected for removal.

        Returns:
            int: How many profiles refer to at least one of the selected skills.
        """
        return (
            FreelancerProfile.objects.filter(skills__in=objs).distinct().count()
            + ClientProfile.objects.filter(interests__in=objs).distinct().count()
        )

    @staticmethod
    def _in_use_summary(referring_profiles: int) -> str:
        """
        Build the refusal message reporting how many profiles are affected.

        Reports the count only. Individual profiles are never listed.

        Args:
            referring_profiles: How many profiles refer to the selected skills.

        Returns:
            str: The translated summary line carrying the count.
        """
        return ngettext(
            "Still in use by %(count)d profile. A skill can only be removed"
            " once no profile refers to it.",
            "Still in use by %(count)d profiles. A skill can only be removed"
            " once no profile refers to it.",
            referring_profiles,
        ) % {"count": referring_profiles}
