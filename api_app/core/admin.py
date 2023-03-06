from django.contrib import admin
from django.db.models import JSONField
from prettyjson import PrettyJSONWidget

from api_app.core.models import AbstractConfig


class AbstractReportAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "job",
        "status",
        "start_time",
        "end_time",
    )
    list_display_links = ("id",)
    search_fields = ("name",)

    def has_add_permission(self, request):
        return False


class JsonViewerAdminView(admin.ModelAdmin):
    formfield_overrides = {
        JSONField: {"widget": PrettyJSONWidget(attrs={"initial": "parsed"})}
    }


class AbstractConfigAdminView(JsonViewerAdminView):
    list_display = (
        "name",
        "python_module",
        "params_names",
        "secrets_names",
        "disabled",

    )
    search_fields = (
        "name",
    )
    # allow to clone the object
    save_as = True

    def params_names(self, instance:AbstractConfig):
        return list(instance.params.keys())

    def secrets_names(self, instance: AbstractConfig):
        return list(instance.secrets.keys())
