"""
Django admin configuration for the accounts app.

Registers Freelancer and Client models with customized interfaces including
list_display, search, filters, fieldset grouping, and bulk actions.
"""

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from accounts.models.freelancer import Freelancer
from accounts.models.client import Client


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
    list_filter = ("is_active", "is_available", "is_staff", "created_at")
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

    actions = ["activate_accounts", "deactivate_accounts", "toggle_availability"]

    @admin.display(description=_("Status"))
    def status_badge(self, obj: Freelancer) -> str:
        """Return a colored HTML badge for the account activation status."""
        color = "green" if obj.is_active else "red"
        label = _("Active") if obj.is_active else _("Inactive")
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            label,
        )

    @admin.display(description=_("Availability"))
    def availability_badge(self, obj: Freelancer) -> str:
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

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Bulk-activate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Successfully activated {updated} accounts.")

    @admin.action(description=_("Deactivate selected accounts"))
    def deactivate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Bulk-deactivate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Successfully deactivated {updated} accounts.")

    @admin.action(description=_("Toggle availability of selected freelancers"))
    def toggle_availability(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Invert the is_available flag for each selected freelancer individually."""
        for obj in queryset:
            obj.is_available = not obj.is_available
            obj.save(update_fields=["is_available"])
        self.message_user(
            request, f"Toggled availability for {queryset.count()} freelancers."
        )


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    """
    Admin interface for the Client model.

    Provides list display with status badges, fieldset grouping,
    search and filter controls, and bulk actions for account and availability management.
    """

    list_display = (
        "name",
        "email",
        "status_badge",
        "created_at_display",
    )

    list_display_links = ("name", "email")
    list_filter = ("is_active", "is_staff", "created_at")
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

    @admin.display(description=_("Status"))
    def status_badge(self, obj: Client) -> str:
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

    @admin.action(description=_("Activate selected accounts"))
    def activate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Bulk-activate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Successfully activated {updated} accounts.")

    @admin.action(description=_("Deactivate selected accounts"))
    def deactivate_accounts(self, request: HttpRequest, queryset: QuerySet) -> None:
        """Bulk-deactivate all accounts in the queryset with a single UPDATE query."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Successfully deactivated {updated} accounts.")
