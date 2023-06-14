# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.db.models import JSONField
from prettyjson import PrettyJSONWidget

from api_app.core.forms import ParameterInlineForm
from api_app.core.models import AbstractConfig, Parameter
from api_app.models import PluginConfig


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

    @staticmethod
    def has_add_permission(request):
        return False


class JsonViewerAdminView(admin.ModelAdmin):
    formfield_overrides = {
        JSONField: {"widget": PrettyJSONWidget(attrs={"initial": "parsed"})}
    }


class PluginConfigInline(admin.TabularInline):
    model = PluginConfig
    extra = 1
    max_num = 1
    fields = ["value"]


@admin.register(Parameter)
class ParameterAdminView(admin.ModelAdmin):
    inlines = [PluginConfigInline]
    search_fields = ["name"]
    list_filter = ["is_secret"]
    list_display = ParameterInlineForm.Meta.fields
    fields = list_display


class ParameterInline(admin.TabularInline):
    model = Parameter
    list_display = ParameterAdminView.list_display
    fields = list_display + ("default",)
    extra = 0
    show_change_link = True
    form = ParameterInlineForm


class AbstractConfigAdminView(JsonViewerAdminView):
    list_display = ("name", "description", "disabled", "disabled_in_orgs")
    search_fields = ("name",)
    # allow to clone the object
    save_as = True

    @staticmethod
    def disabled_in_orgs(instance: AbstractConfig):
        return [org.name for org in instance.disabled_in_organizations.all()]


class PythonConfigAdminView(AbstractConfigAdminView):
    inlines = [ParameterInline]
    list_display = (
        "name",
        "python_module",
        "params",
        "secrets",
        "disabled",
        "disabled_in_orgs",
    )

    @staticmethod
    def params(instance: AbstractConfig):
        return list(
            instance.parameters.filter(is_secret=False).values_list("name", flat=True)
        )

    @staticmethod
    def secrets(instance: AbstractConfig):
        return list(
            instance.parameters.filter(is_secret=True).values_list("name", flat=True)
        )
