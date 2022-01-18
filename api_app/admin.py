# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from certego_saas.user.admin import AbstractUserAdmin
from certego_saas.user.models import User
from django.conf import settings
from django.contrib import admin
from durin.admin import AuthTokenAdmin
from durin.models import AuthToken, Client

from .models import Job, Tag


@admin.register(User)
class UserAdminView(AbstractUserAdmin):
    pass


@admin.register(Job)
class JobAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "status",
        "user",
        "observable_name",
        "observable_classification",
        "file_name",
        "file_mimetype",
        "received_request_time",
    )
    list_display_link = (
        "id",
        "user",
        "status",
    )
    search_fields = (
        "md5",
        "observable_name",
        "file_name",
    )


@admin.register(Tag)
class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


# durin app (AuthToken model) customization


class CustomAuthTokenAdmin(AuthTokenAdmin):
    """
    Custom admin view for AuthToken model
    """

    exclude = []
    raw_id_fields = ("user",)
    readonly_fields = ("token", "expiry", "created", "expires_in")

    def get_fieldsets(self, request, obj=None):
        if not obj:
            return [
                (
                    "Create token for PyIntelOwl",
                    {
                        "fields": ("user",),
                        "description": """
                    <h3>Token will be auto-generated on save.</h3>
                    <h3>This token will be valid for 10 years.</h3>
                """,
                    },
                ),
            ]
        return super().get_fieldsets(request, obj)

    def has_change_permission(self, *args, **kwargs):
        return False

    def save_model(self, request, obj, form, change):
        obj.client = Client.objects.get(
            name=settings.REST_DURIN["API_ACCESS_CLIENT_NAME"]
        )
        super(CustomAuthTokenAdmin, self).save_model(request, obj, form, change)


# Unregister Client admin view
admin.site.unregister(Client)
# Unregister the default admin view for AuthToken
admin.site.unregister(AuthToken)
# Register our custom admin view for AuthToken
admin.site.register(AuthToken, CustomAuthTokenAdmin)
