from django.contrib import admin
from django.db.models import JSONField
from prettyjson import PrettyJSONWidget

from api_app.core.models import AbstractConfig


class AbstractReportAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "config",
        "job",
        "status",
        "start_time",
        "end_time",
    )
    list_display_links = ("id",)
    search_fields = ("config",)

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
        "disabled_in_orgs",
    )
    search_fields = ("name",)
    # allow to clone the object
    save_as = True

    def params_names(self, instance: AbstractConfig):
        return list(instance.params.keys())

    def secrets_names(self, instance: AbstractConfig):
        return list(instance.secrets.keys())

    def disabled_in_orgs(self, instance: AbstractConfig):
        return [org.name for org in instance.disabled_in_organizations.all()]
