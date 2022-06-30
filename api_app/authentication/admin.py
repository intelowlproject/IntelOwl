# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.contrib import admin
from durin.admin import AuthTokenAdmin
from durin.models import AuthToken, Client

from certego_saas.user.admin import AbstractUserAdmin
from certego_saas.user.models import User

# certego-saas


@admin.register(User)
class UserAdminView(AbstractUserAdmin):
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_active",
        "is_staff",
    )


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

    @staticmethod
    def has_change_permission(*args, **kwargs):
        return False

    def save_model(self, request, obj, form, change):
        obj.client = Client.objects.get(
            name=settings.REST_DURIN["API_ACCESS_CLIENT_NAME"]
        )
        super().save_model(request, obj, form, change)


# Unregister the default admin view for AuthToken
admin.site.unregister(AuthToken)
# Register our custom admin view for AuthToken
admin.site.register(AuthToken, CustomAuthTokenAdmin)
