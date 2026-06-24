"""
Django admin configuration for the accounts app.

Registers Freelancer, Client, and StaffUser models with customized interfaces
including list_display, search, filters, fieldset grouping, and bulk actions.
"""

from django.contrib import admin, messages
from django.core.exceptions import ValidationError
from django.db.models import QuerySet
from django.forms import ModelForm
from django.http import HttpRequest
from django.utils.html import format_html
from django.utils.safestring import SafeString
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from accounts.models.client import Client
from accounts.models.freelancer import Freelancer
from accounts.models.staff_user import StaffUser


@admin.register(Freelancer)
class FreelancerAdmin(admin.ModelAdmin):
    """
    Admin interface for the Freelancer model.

    Provides list display with status and availability badges, fieldset grouping,
    search and filter controls, and bulk actions for account and availability management.
    """

    list_display = (
        "id",
        "name",
        "email",
        "status_badge",
        "availability_badge",
        "created_at_display",
    )
    list_display_links = ("name", "email")
    list_filter = ("is_active", "is_available", "created_at")
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

    actions = ["activate_accounts", "set_available", "set_unavailable"]

    # --- Permission overrides ---

    def has_delete_permission(
        self, request: HttpRequest, obj: Freelancer | None = None
    ) -> bool:
        """Disable deletion for all users. Accounts must be deactivated, not deleted."""
        return False

    def save_model(
        self, request: HttpRequest, obj: Freelancer, form: ModelForm, change: bool
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

    # --- Display methods ---

    @admin.display(description=_("Status"))
    def status_badge(self, obj: Freelancer) -> SafeString:
        """Return a colored HTML badge for the account activation status."""
        color = "green" if obj.is_active else "red"
        label = _("Active") if obj.is_active else _("Inactive")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )

    @admin.display(description=_("Availability"))
    def availability_badge(self, obj: Freelancer) -> SafeString:
        """Return a colored HTML badge for the freelancer availability status."""
        color = "blue" if obj.is_available else "orange"
        label = _("Available") if obj.is_available else _("Busy")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )

    @admin.display(description=_("Created At"), ordering="created_at")
    def created_at_display(self, obj: Freelancer) -> str:
        """Format the creation timestamp as YYYY-MM-DD HH:MM for list display."""
        return obj.created_at.strftime("%Y-%m-%d %H:%M")

    # --- Bulk actions ---

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
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

    @admin.action(description=_("Set selected freelancers as available"))
    def set_available(self, request: HttpRequest, queryset: QuerySet) -> None:
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
    def set_unavailable(self, request: HttpRequest, queryset: QuerySet) -> None:
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


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    """
    Admin interface for the Client model.

    Provides list display with status badges, fieldset grouping,
    search and filter controls, and bulk actions for account management.
    """

    list_display = (
        "name",
        "email",
        "status_badge",
        "created_at_display",
    )

    list_display_links = ("name", "email")
    list_filter = ("is_active", "created_at")
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

    actions = ["activate_accounts", "deactivate_accounts"]

    # --- Permission overrides ---

    def has_delete_permission(
        self, request: HttpRequest, obj: Client | None = None
    ) -> bool:
        """Disable deletion for all users. Accounts must be deactivated, not deleted."""
        return False

    def save_model(
        self, request: HttpRequest, obj: Client, form: ModelForm, change: bool
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

    # --- Display methods ---

    @admin.display(description=_("Status"))
    def status_badge(self, obj: Client) -> SafeString:
        """Return a colored HTML badge for the account activation status."""
        color = "green" if obj.is_active else "red"
        label = _("Active") if obj.is_active else _("Inactive")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )

    @admin.display(description=_("Created At"), ordering="created_at")
    def created_at_display(self, obj: Client) -> str:
        """Format the creation timestamp as YYYY-MM-DD HH:MM for list display."""
        return obj.created_at.strftime("%Y-%m-%d %H:%M")

    # --- Bulk actions ---

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
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

    @admin.action(description=_("Deactivate selected accounts"))
    def deactivate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
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


@admin.register(StaffUser)
class StaffUserAdmin(admin.ModelAdmin):
    """
    Admin interface for the StaffUser model.

    Provides list display, fieldset grouping, search and filter controls,
    and bulk actions for account management.

    StaffUser represents platform administrators and operators.
    This interface is intentionally minimal and restrictive.

    StaffUser creation via the Admin add form is supported — no
    has_add_permission restriction is applied. However, is_superuser is
    always readonly in this interface (see get_readonly_fields), so the
    Admin form cannot create or promote a superuser. Superuser
    creation and promotion are shell-only operations, performed via
    the createsuperuser management command or the Django shell.
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

    # is_superuser is always readonly: promoting to superuser is a shell-only operation
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

    # --- Permission overrides ---

    def has_delete_permission(
        self, request: HttpRequest, obj: StaffUser | None = None
    ) -> bool:
        """Disable deletion for all users. Accounts must be deactivated, not deleted."""
        return False

    def get_readonly_fields(
        self, request: HttpRequest, obj: StaffUser | None = None
    ) -> tuple[str, ...]:
        """
        Make is_staff read-only for non-superusers.

        is_superuser is always read-only regardless of the requesting user.
        Promoting a StaffUser to superuser must be done via the Django shell.
        """
        base = self.readonly_fields
        if not request.user.is_superuser:
            return base + ("is_staff",)
        return base

    def save_model(
        self, request: HttpRequest, obj: StaffUser, form: ModelForm, change: bool
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

    # --- Display methods ---

    @admin.display(description=_("Created At"), ordering="created_at")
    def created_at_display(self, obj: StaffUser) -> str:
        """Format the creation timestamp as YYYY-MM-DD HH:MM for list display."""
        return obj.created_at.strftime("%Y-%m-%d %H:%M")

    # --- Bulk actions ---

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
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

    @admin.action(description=_("Deactivate selected accounts"))
    def deactivate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
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
