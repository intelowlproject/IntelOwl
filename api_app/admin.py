# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.db.models import JSONField
from prettyjson.widgets import PrettyJSONWidget

from .forms import ParameterInlineForm
from .models import AbstractConfig, Job, Parameter, PluginConfig, PythonModule, Tag
from .tabulars import (
    ParameterInline,
    PluginConfigInlineForParameter,
    PluginConfigInlineForPythonConfig,
)


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
        "analyzers_executed",
        "connectors_executed",
        "visualizers_executed",
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
    list_filter = (
        "status",
        "user",
    )

    def analyzers_executed(self, instance: Job):  # noqa
        return [analyzer.name for analyzer in instance.analyzers_to_execute.all()]

    def connectors_executed(self, instance: Job):  # noqa
        return [connector.name for connector in instance.connectors_to_execute.all()]

    def visualizers_executed(self, instance: Job):  # noqa
        return [visualizer.name for visualizer in instance.visualizers_to_execute.all()]


@admin.register(Tag)
class TagAdminView(admin.ModelAdmin):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


@admin.register(PluginConfig)
class PluginConfigAdminView(admin.ModelAdmin):
    list_display = (
        "get_config",
        "parameter",
        "for_organization",
        "get_owner",
        "get_type",
        "value",
    )
    search_fields = ["parameter__name", "value"]
    list_filter = ("for_organization",)

    @admin.display(description="Config")
    def get_config(self, instance: PluginConfig):
        return instance.config.name

    @admin.display(description="Owner")
    def get_owner(self, instance: PluginConfig):
        if instance.owner:
            return instance.owner.username
        return "default"

    @admin.display(description="Type")
    def get_type(self, instance: PluginConfig):
        return instance.parameter.type


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


@admin.register(Parameter)
class ParameterAdminView(admin.ModelAdmin):
    inlines = [PluginConfigInlineForParameter]
    search_fields = ["name"]
    list_filter = ["is_secret"]
    list_display = ParameterInlineForm.Meta.fields
    fields = list_display


@admin.register(PythonModule)
class PythonModuleAdminView(admin.ModelAdmin):
    list_display = ["module", "base_path", "get_parameters", "get_secrets"]
    search_fields = ["module", "base_path"]
    list_filter = ["base_path"]
    inlines = [ParameterInline]

    @admin.display(description="Parameters")
    def get_parameters(self, obj: PythonModule):
        return list(obj.parameters.filter(is_secret=False).order_by("-name"))

    @admin.display(description="Secrets")
    def get_secrets(self, obj: PythonModule):
        return list(obj.parameters.filter(is_secret=True).order_by("-name"))


class AbstractConfigAdminView(JsonViewerAdminView):
    list_display = ("name", "description", "disabled", "disabled_in_orgs")
    search_fields = ("name",)
    # allow to clone the object
    save_as = True

    @admin.display(description="Disabled in orgs")
    def disabled_in_orgs(self, instance: AbstractConfig):
        return [org.name for org in instance.disabled_in_organizations.all()]


class PythonConfigAdminView(AbstractConfigAdminView):
    list_display = (
        "name",
        "python_module",
        "disabled",
        "disabled_in_orgs",
    )
    inlines = [PluginConfigInlineForPythonConfig]
