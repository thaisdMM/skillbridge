"""
Django admin configuration for the accounts app.

Registers Freelancer, Client, and StaffUser models with customized interfaces
including list_display, search, filters, fieldset grouping, and bulk actions.

Shared admin behavior is consolidated into a non-registered base class
(BaseAccountAdmin) and two opt-in mixins (StatusBadgeMixin and
ProfilePresenceMixin), so each registered admin composes exactly the members
it needs without duplicating method bodies. Bulk deactivation lives on
StaffUserAdmin, the only admin that exposes it.

Profiles are administered inside the account screen they belong to rather than
on screens of their own, so the profile inlines live here beside the account
admins that own them. This module imports profiles.models, never profiles.admin.
"""

from typing import Any

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.widgets import RelatedFieldWidgetWrapper
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Exists, OuterRef, QuerySet
from django.forms import ModelForm
from django.http import HttpRequest
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from accounts.models.base import BaseUser
from accounts.models.client import Client
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser
from profiles.models.client_profile import ClientProfile
from profiles.models.freelancer_profile import FreelancerProfile


class BaseAccountAdmin(admin.ModelAdmin):
    """
    Base admin holding the behavior shared by all account admins.

    Not registered against any model. Provides the three members common to
    FreelancerAdmin, ClientAdmin, and StaffUserAdmin: deletion is disabled,
    the password gap is closed on save, and the creation timestamp is
    formatted for display.

    All shared signatures are typed against BaseUser, the common abstract
    parent of the three concrete models, because every field these methods
    touch (password, is_active, created_at) is declared on BaseUser.
    """

    def has_delete_permission(
        self, request: HttpRequest, obj: BaseUser | None = None
    ) -> bool:
        """Disable deletion for all users. Accounts must be deactivated, not deleted."""
        return False

    def save_model(
        self, request: HttpRequest, obj: BaseUser, form: ModelForm, change: bool
    ) -> None:
        """
        Ensure password is never saved as plain text or empty string.

        When a user is created via the admin form without a password,
        set_unusable_password() marks the account correctly so Django
        does not treat the empty string as a valid credential.
        """
        if not obj.password:
            obj.set_unusable_password()
        super().save_model(request, obj, form, change)

    @admin.display(description=_("Created At"), ordering="created_at")
    def created_at_display(self, obj: BaseUser) -> str:
        """Format the creation timestamp as YYYY-MM-DD HH:MM for list display."""
        return obj.created_at.strftime("%Y-%m-%d %H:%M")


class ProfileInlineForm(forms.ModelForm):
    """
    Form used by both profile sections.

    Presents errors raised against fields the section renders hidden, which
    would otherwise reach the page with no place to be displayed. The profile
    section shows them above its fields.
    """

    def full_clean(self) -> None:
        """
        Validate the form and move errors raised against hidden fields.

        Each error keeps its original code; only where it is displayed changes.
        """
        super().full_clean()
        hidden_fields_with_errors = {
            name for name, field in self.fields.items() if field.widget.is_hidden
        } & set(self._errors)
        for name in hidden_fields_with_errors:
            for error in self._errors.pop(name).as_data():
                self.add_error(None, error)


class BaseProfileInline(admin.StackedInline):
    """
    Base inline holding the behavior shared by both profile sections.

    Not attached to any model. Provides the members common to
    FreelancerProfileInline and ClientProfileInline: the section presents at
    most one profile and offers no way to add a second, no removal control is
    rendered, the timestamps are shown read-only, no related field offers a
    control that creates a record on the other side of the relation, and every
    error reaches the page where it can be read.

    Subclasses supply the model and the fieldsets.
    """

    form = ProfileInlineForm
    extra = 1
    max_num = 1
    can_delete = False
    readonly_fields = ("created_at", "updated_at")

    def has_delete_permission(
        self, request: HttpRequest, obj: BaseUser | None = None
    ) -> bool:
        """Disable deletion for all profiles. A profile is retired with its account, never deleted."""
        return False

    def formfield_for_dbfield(
        self, db_field: models.Field, request: HttpRequest, **kwargs: Any
    ) -> forms.Field:
        """
        Strip the add-related control from every related field on the section.

        Args:
            db_field: The model field the form field is being built for.
            request: The current admin request.

        Returns:
            forms.Field: The form field, carrying no add-related control when
                it renders a related field.
        """
        formfield = super().formfield_for_dbfield(db_field, request, **kwargs)
        if isinstance(formfield.widget, RelatedFieldWidgetWrapper):
            formfield.widget.can_add_related = False
        return formfield


class StatusBadgeMixin:
    """
    Mixin providing the account activation status badge.

    Opted into by FreelancerAdmin and ClientAdmin. StaffUserAdmin does not
    inherit it, keeping its raw is_active/is_staff columns in list_display.
    """

    @admin.display(description=_("Status"))
    def status_badge(self, obj: BaseUser) -> SafeString:
        """
        Build the account activation status badge for list display.

        Returns:
            A SafeString HTML badge, green for active and red for inactive.
        """
        color = "green" if obj.is_active else "red"
        label = _("Active") if obj.is_active else _("Inactive")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )


class HasProfileFilter(admin.SimpleListFilter):
    """
    Filter narrowing an account list to the accounts that have a profile.

    Offered on the freelancer and client lists only. Both account models reach
    their profile through the same reverse accessor, so one filter serves both.
    """

    title = _("profile")
    parameter_name = "has_profile"

    def lookups(
        self, request: HttpRequest, model_admin: admin.ModelAdmin
    ) -> tuple[tuple[str, str], ...]:
        """
        List the two groups an administrator can narrow the list to.

        Returns:
            The value and label of each choice offered by the filter.
        """
        return (
            ("yes", _("With a profile")),
            ("no", _("Without a profile")),
        )

    def queryset(
        self, request: HttpRequest, queryset: QuerySet[BaseUser]
    ) -> QuerySet[BaseUser]:
        """
        Narrow the list to the group the administrator selected.

        Returns:
            The accounts of the selected group, or the untouched queryset when
            no choice is active.
        """
        if self.value() == "yes":
            return queryset.filter(profile__isnull=False)
        if self.value() == "no":
            return queryset.filter(profile__isnull=True)
        return queryset


class ProfilePresenceMixin:
    """
    Mixin providing the profile presence badge on an account list.

    Opted into by FreelancerAdmin and ClientAdmin. StaffUserAdmin does not
    inherit it, so no profile column reaches the staff list.

    The badge reads an annotation resolved once for the whole page rather than
    the reverse accessor, which would cost one query per row.
    """

    def get_queryset(self, request: HttpRequest) -> QuerySet[BaseUser]:
        """
        Annotate every account on the page with whether it has a profile.

        The profile model is read from the reverse relation the account model
        declares, so the mixin serves both account lists unchanged.

        Returns:
            The changelist queryset carrying the has_profile annotation.
        """
        profile_relation = self.model._meta.get_field("profile")
        profiles = profile_relation.related_model.objects.filter(user=OuterRef("pk"))
        return super().get_queryset(request).annotate(has_profile=Exists(profiles))

    @admin.display(description=_("Profile"))
    def profile_badge(self, obj: BaseUser) -> SafeString:
        """
        Build the profile presence badge for list display.

        Returns:
            A SafeString HTML badge, green when the account has a profile and
            red when it has none.
        """
        color = "green" if obj.has_profile else "red"
        label = _("Yes") if obj.has_profile else _("No")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )


class FreelancerProfileInline(BaseProfileInline):
    """
    Profile section rendered inside the freelancer account screen.

    Presents the rate, experience, portfolio link, skills and biography of the
    freelancer whose account screen holds it. Skills are attached and detached
    through a two-column selector listing the existing vocabulary.
    """

    model = FreelancerProfile
    filter_horizontal = ("skills",)

    fieldsets = (
        (
            None,
            {
                "fields": ("hourly_rate", "years_of_experience", "portfolio_url"),
            },
        ),
        (
            _("Skills"),
            {
                "fields": ("skills",),
            },
        ),
        (
            _("Biography"),
            {
                "fields": ("bio",),
            },
        ),
        (
            _("Important Dates"),
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(Freelancer)
class FreelancerAdmin(ProfilePresenceMixin, StatusBadgeMixin, BaseAccountAdmin):
    """
    Admin interface for the Freelancer model.

    Provides list display with status, availability and profile presence
    badges, fieldset grouping, search and filter controls, bulk account
    activation, bulk availability management, and the freelancer profile
    section.
    """

    list_display = (
        "id",
        "name",
        "email",
        "status_badge",
        "availability_badge",
        "profile_badge",
        "created_at_display",
    )
    list_display_links = ("name", "email")
    list_filter = ("is_active", "is_available", HasProfileFilter, "created_at")
    search_fields = ("name", "email")
    ordering = ("-created_at",)
    list_per_page = 25

    readonly_fields = ("created_at", "last_login")

    fieldsets = (
        (
            None,
            {
                "fields": ("name", "email"),
            },
        ),
        (
            _("Account Status"),
            {
                "fields": ("is_active", "is_available"),
            },
        ),
        (
            _("Important Dates"),
            {
                "fields": ("created_at", "last_login"),
                "classes": ("collapse",),
            },
        ),
    )

    inlines = (FreelancerProfileInline,)

    actions = ["activate_accounts", "set_available", "set_unavailable"]

    @admin.display(description=_("Availability"))
    def availability_badge(self, obj: Freelancer) -> SafeString:
        """
        Build the freelancer availability badge for list display.

        Returns:
            A SafeString HTML badge, blue for available and orange for busy.
        """
        color = "blue" if obj.is_available else "orange"
        label = _("Available") if obj.is_available else _("Busy")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )

    @admin.action(description=_("Set selected freelancers as available"))
    def set_available(
        self, request: HttpRequest, queryset: QuerySet[Freelancer]
    ) -> None:
        """Set is_available=True for each selected freelancer, skipping inactive ones."""
        updated = 0
        skipped = 0
        for obj in queryset:
            obj.is_available = True
            try:
                obj.clean()
            except ValidationError:
                skipped += 1
                continue
            obj.save(update_fields=["is_available"])
            updated += 1
        if updated:
            self.message_user(
                request,
                ngettext(
                    "%(count)d freelancer set as available.",
                    "%(count)d freelancers set as available.",
                    updated,
                )
                % {"count": updated},
            )
        if skipped:
            self.message_user(
                request,
                ngettext(
                    "%(count)d freelancer skipped — an inactive freelancer cannot be available.",
                    "%(count)d freelancers skipped — an inactive freelancer cannot be available.",
                    skipped,
                )
                % {"count": skipped},
                level=messages.WARNING,
            )

    @admin.action(description=_("Set selected freelancers as unavailable"))
    def set_unavailable(
        self, request: HttpRequest, queryset: QuerySet[Freelancer]
    ) -> None:
        """Set is_available=False for all selected freelancers in a single UPDATE query."""
        updated = queryset.update(is_available=False)
        self.message_user(
            request,
            ngettext(
                "%(count)d freelancer set as unavailable.",
                "%(count)d freelancers set as unavailable.",
                updated,
            )
            % {"count": updated},
        )

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(
        self, request: HttpRequest, queryset: QuerySet[Freelancer]
    ) -> None:
        """Bulk-activate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            ngettext(
                "Successfully activated %(count)d account.",
                "Successfully activated %(count)d accounts.",
                updated,
            )
            % {"count": updated},
        )


class ClientProfileInline(BaseProfileInline):
    """
    Profile section rendered inside the client account screen.

    Presents the company, budget, website, interests and biography of the
    client whose account screen holds it. Interests are attached and detached
    through a two-column selector listing the existing vocabulary.
    """

    model = ClientProfile
    filter_horizontal = ("interests",)

    fieldsets = (
        (
            None,
            {
                "fields": ("company_name", "max_budget", "website_url"),
            },
        ),
        (
            _("Interests"),
            {
                "fields": ("interests",),
            },
        ),
        (
            _("Biography"),
            {
                "fields": ("bio",),
            },
        ),
        (
            _("Important Dates"),
            {
                "fields": ("created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(Client)
class ClientAdmin(ProfilePresenceMixin, StatusBadgeMixin, BaseAccountAdmin):
    """
    Admin interface for the Client model.

    Provides list display with status and profile presence badges, fieldset
    grouping, search and filter controls, and bulk activation of accounts.
    """

    list_display = (
        "name",
        "email",
        "status_badge",
        "profile_badge",
        "created_at_display",
    )

    list_display_links = ("name", "email")
    list_filter = ("is_active", HasProfileFilter, "created_at")
    search_fields = ("name", "email")
    ordering = ("-created_at",)
    list_per_page = 25

    readonly_fields = ("created_at", "last_login")

    fieldsets = (
        (
            None,
            {
                "fields": ("name", "email"),
            },
        ),
        (
            _("Account Status"),
            {
                "fields": ("is_active",),
            },
        ),
        (
            _("Important Dates"),
            {
                "fields": ("created_at", "last_login"),
                "classes": ("collapse",),
            },
        ),
    )

    inlines = (ClientProfileInline,)

    actions = ["activate_accounts"]

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(
        self, request: HttpRequest, queryset: QuerySet[Client]
    ) -> None:
        """Bulk-activate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            ngettext(
                "Successfully activated %(count)d account.",
                "Successfully activated %(count)d accounts.",
                updated,
            )
            % {"count": updated},
        )


@admin.register(StaffUser)
class StaffUserAdmin(BaseAccountAdmin):
    """
    Admin interface for the StaffUser model.

    Manages platform administrators and operators with raw is_active and
    is_staff columns in list display, fieldset grouping, search and filter
    controls, and bulk activation and deactivation of accounts.

    is_superuser is always read-only here; superuser creation and promotion
    are performed via the shell, not this form.
    """

    list_display = (
        "name",
        "email",
        "is_active",
        "is_staff",
        "created_at_display",
    )

    list_display_links = ("name", "email")
    list_filter = ("is_active", "created_at")
    search_fields = ("name", "email")
    ordering = ("-created_at",)
    list_per_page = 25

    readonly_fields = ("created_at", "last_login", "is_superuser")

    fieldsets = (
        (
            None,
            {
                "fields": ("name", "email"),
            },
        ),
        (
            _("Account Status"),
            {
                "fields": ("is_active",),
            },
        ),
        (
            _("Administrative"),
            {
                "fields": ("is_staff", "is_superuser"),
                "classes": ("collapse",),
            },
        ),
        (
            _("Important Dates"),
            {
                "fields": ("created_at", "last_login"),
                "classes": ("collapse",),
            },
        ),
    )

    actions = ["activate_accounts", "deactivate_accounts"]

    @admin.action(description=_("Deactivate selected accounts"))
    def deactivate_accounts(
        self, request: HttpRequest, queryset: QuerySet[BaseUser]
    ) -> None:
        """Bulk-deactivate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            ngettext(
                "Successfully deactivated %(count)d account.",
                "Successfully deactivated %(count)d accounts.",
                updated,
            )
            % {"count": updated},
        )

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(
        self, request: HttpRequest, queryset: QuerySet[StaffUser]
    ) -> None:
        """Activate each selected staff account, skipping those without staff status."""
        updated = 0
        skipped = 0
        for obj in queryset:
            obj.is_active = True
            try:
                obj.clean()
            except ValidationError:
                skipped += 1
                continue
            obj.save(update_fields=["is_active"])
            updated += 1
        if updated:
            self.message_user(
                request,
                ngettext(
                    "Successfully activated %(count)d account.",
                    "Successfully activated %(count)d accounts.",
                    updated,
                )
                % {"count": updated},
            )
        if skipped:
            self.message_user(
                request,
                ngettext(
                    "%(count)d account skipped — an active staff account requires"
                    " staff status. Grant is_staff before activating, or leave the"
                    " account inactive.",
                    "%(count)d accounts skipped — an active staff account requires"
                    " staff status. Grant is_staff before activating, or leave the"
                    " accounts inactive.",
                    skipped,
                )
                % {"count": skipped},
                level=messages.WARNING,
            )

    def get_readonly_fields(
        self, request: HttpRequest, obj: StaffUser | None = None
    ) -> tuple[str, ...]:
        """
        Make is_staff read-only for non-superusers.

        is_superuser is always read-only regardless of the requesting user.

        Returns:
            The tuple of read-only field names for the current request.
        """
        base = self.readonly_fields
        if not request.user.is_superuser:
            return base + ("is_staff",)
        return base
