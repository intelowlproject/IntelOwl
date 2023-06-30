# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.db.models import JSONField

from .forms import ParameterInlineForm
from .models import AbstractConfig, Job, Parameter, PluginConfig, Tag
from .tabulars import PluginConfigInline


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
class PluginCredentialAdminView(admin.ModelAdmin):
    list_display = ("id", "value", "parameter_name", "for_organization", "owner_name")
    search_fields = ["parameter__name", "value"]
    list_filter = (
        "for_organization",
        "owner",
        "parameter__analyzer_config__name",
        "parameter__connector_config__name",
        "parameter__visualizer_config__name",
    )

    @staticmethod
    def parameter_name(instance: PluginConfig):
        return instance.parameter.name

    @staticmethod
    def owner_name(instance: PluginConfig):
        if instance.owner:
            return instance.owner.name
        return None


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
