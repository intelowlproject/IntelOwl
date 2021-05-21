# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from durin.admin import AuthTokenAdmin
from durin.models import AuthToken, Client
from guardian.admin import GuardedModelAdmin

from .models import Job, Tag


class JobAdminView(GuardedModelAdmin):
    list_display = (
        "id",
        "status",
        "source",
        "observable_name",
        "observable_classification",
        "file_name",
        "file_mimetype",
        "received_request_time",
    )
    list_display_link = ("id", "status")
    search_fields = ("source", "md5", "observable_name")


class TagAdminView(GuardedModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


# Auth Token stuff
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
        obj.client = Client.objects.get(name="pyintelowl")
        super(CustomAuthTokenAdmin, self).save_model(request, obj, form, change)


admin.site.register(Job, JobAdminView)
admin.site.register(Tag, TagAdminView)
# Unregister Client admin view
admin.site.unregister(Client)
# Unregister the default admin view for AuthToken
admin.site.unregister(AuthToken)
# Register our custom admin view for AuthToken
admin.site.register(AuthToken, CustomAuthTokenAdmin)
