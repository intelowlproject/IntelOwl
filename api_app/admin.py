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

    fieldsets = []
    exclude = []
    raw_id_fields = ("user",)
    readonly_fields = ("token", "expiry", "client")
    __fieldsets_custom = [
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

    def add_view(self, request, extra_content=None):
        self.fieldsets = self.__fieldsets_custom
        return super(CustomAuthTokenAdmin, self).add_view(request)

    def has_change_permission(self, *args, **kwargs):
        return False

    def save_model(self, request, obj, form, change):
        client = Client.objects.get(name="pyintelowl")
        obj = AuthToken.objects.create(
            user=obj.user, client=client
        )  # lgtm [py/unused-local-variable]


admin.site.register(Job, JobAdminView)
admin.site.register(Tag, TagAdminView)
# Unregister Client admin view
admin.site.unregister(Client)
# Unregister the default admin view for AuthToken
admin.site.unregister(AuthToken)
# Register our custom admin view for AuthToken
admin.site.register(AuthToken, CustomAuthTokenAdmin)
