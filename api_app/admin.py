from django.contrib import admin

from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from .models import Job, Tag
from intel_owl.settings import CLIENT_TOKEN_LIFETIME_DAYS, SIMPLE_JWT as jwt_settings


class JobAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "source",
        "observable_name",
        "status",
        "observable_classification",
        "file_mimetype",
        "received_request_time",
    )
    list_display_link = ("id", "status")
    search_fields = ("source", "md5", "observable_name")


class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


# SimpleJWT stuff
class CustomOutstandingTokenAdmin(OutstandingTokenAdmin):
    """
    Custom admin view for OutstandingToken model of simplejwt package\n
    allows bulk deletion and refresh token creation
    """

    # default actions
    actions = []

    # searchable fields
    search_fields = (
        "user__username",
        "user__id",
        "jti",
    )

    __fieldsets_custom = [
        (
            "Create API Token For",
            {
                "fields": ("user", "token",),
                "description": f"""
                    <h3>Token will be auto-generated on save.</h3>
                    <h5>Please note that this token,</h5>
                    <ol>
                      <li>can only be used with the PyIntelOwl client.</li>
                      <li>is rotated on every authenticated request
                      and saves itself via pyintelowl</li>
                      <li>
                        automatically expires if goes
                        unused for {CLIENT_TOKEN_LIFETIME_DAYS} days.
                    </li>
                    </ol>
                """,
            },
        ),
    ]

    def add_view(self, request, extra_content=None):
        self.fieldsets = self.__fieldsets_custom
        return super(CustomOutstandingTokenAdmin, self).add_view(request)

    def get_readonly_fields(self, *args, **kwargs):
        fields = [f.name for f in self.model._meta.fields]
        # only user field is writeable
        fields.remove("user")
        return fields

    def has_delete_permission(self, *args, **kwargs):
        return True

    def has_add_permission(self, *args, **kwargs):
        return True

    def has_change_permission(self, *args, **kwargs):
        return False

    def save_model(self, request, obj, form, change):
        if obj.user:
            refresh = RefreshToken()
            # custom claims
            refresh["client"] = "pyintelowl"
            refresh["user_id"] = obj.user.id
            # overwrite lifetime/expiry
            refresh.set_exp(
                lifetime=jwt_settings.get("PYINTELOWL_TOKEN_LIFETIME", None)
            )
            token = OutstandingToken.objects.create(
                user=obj.user,
                jti=refresh.payload["jti"],
                token=str(refresh),
                created_at=refresh.current_time,
                expires_at=datetime_from_epoch(refresh["exp"]),
            )
            return token

        return None


admin.site.register(Job, JobAdminView)
admin.site.register(Tag, TagAdminView)
# Unregister the default admin view for OutstandingToken
admin.site.unregister(OutstandingToken)
# Register our custom admin view for OutstandingToken
admin.site.register(OutstandingToken, CustomOutstandingTokenAdmin)
