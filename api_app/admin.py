from django.contrib import admin

from rest_framework.authtoken.admin import TokenAdmin
from rest_framework.authtoken.models import Token
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
class CustomTokenAdmin(TokenAdmin):
    """
    Custom admin view for TokenAdmin model
    """

    # searchable fields
    search_fields = ("user__username",)

    __fieldsets_custom = [
        (
            "Create API Token For",
            {
                "fields": ("user",),
                "description": """
                    <h3>Token will be auto-generated on save.</h3>
                    <h5>You can use this auth token with the PyIntelOwl client
                     or normal HTTP requests too.</h5>
                """,
            },
        ),
    ]

    def add_view(self, request, extra_content=None):
        self.fieldsets = self.__fieldsets_custom
        return super(CustomTokenAdmin, self).add_view(request)


admin.site.register(Job, JobAdminView)
admin.site.register(Tag, TagAdminView)
# Unregister the default admin view for Token
admin.site.unregister(Token)
# Register our custom admin view for Token
admin.site.register(Token, CustomTokenAdmin)
