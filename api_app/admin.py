# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Any

from django.contrib import admin
from django.contrib.admin import widgets
from django.db.models import JSONField, ManyToManyField
from django.http import HttpRequest
from prettyjson.widgets import PrettyJSONWidget

from .forms import OrganizationPluginConfigurationForm, ParameterInlineForm
from .models import (
    AbstractConfig,
    Job,
    OrganizationPluginConfiguration,
    Parameter,
    PluginConfig,
    PythonModule,
    Tag,
)
from .tabulars import (
    OrganizationPluginConfigurationInLine,
    ParameterInline,
    PluginConfigInlineForParameter,
    PluginConfigInlineForPythonConfig,
)


class CustomAdminView(admin.ModelAdmin):
    formfield_overrides = {
        JSONField: {"widget": PrettyJSONWidget(attrs={"initial": "parsed"})},
    }

    def formfield_for_manytomany(
        self, db_field: ManyToManyField, request: HttpRequest, **kwargs: Any
    ):
        vertical = False
        kwargs["widget"] = widgets.FilteredSelectMultiple(
            verbose_name=db_field.verbose_name, is_stacked=vertical
        )
        return super().formfield_for_manytomany(db_field, request, **kwargs)


@admin.register(Job)
class JobAdminView(CustomAdminView):
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
        "get_tags",
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
    list_filter = ("status", "user", "tags")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        return False

    @admin.display(description="Tags")
    def get_tags(self, instance: Job):
        return [tag.label for tag in instance.tags.all()]

    @staticmethod
    def analyzers_executed(instance: Job):  # noqa
        return [analyzer.name for analyzer in instance.analyzers_to_execute.all()]

    @staticmethod
    def connectors_executed(instance: Job):  # noqa
        return [connector.name for connector in instance.connectors_to_execute.all()]

    @staticmethod
    def visualizers_executed(instance: Job):  # noqa
        return [visualizer.name for visualizer in instance.visualizers_to_execute.all()]


@admin.register(Tag)
class TagAdminView(CustomAdminView):
    list_display = ("id", "label", "color")
    search_fields = ("label", "color")


class ModelWithOwnershipAdminView:
    list_display = (
        "for_organization",
        "get_owner",
    )
    list_filter = ("for_organization", "owner")

    @admin.display(description="Owner")
    def get_owner(self, instance: PluginConfig):
        if instance.owner:
            return instance.owner.username
        return "-"


@admin.register(PluginConfig)
class PluginConfigAdminView(ModelWithOwnershipAdminView, CustomAdminView):
    list_display = (
        "pk",
        "get_config",
        "parameter",
        "for_organization",
        "get_owner",
        "get_type",
        "value",
    ) + ModelWithOwnershipAdminView.list_display

    search_fields = ["parameter__name", "value"]

    @admin.display(description="Config")
    def get_config(self, instance: PluginConfig):
        return instance.config.name

    @admin.display(description="Type")
    def get_type(self, instance: PluginConfig):
        return instance.parameter.type


class AbstractReportAdminView(CustomAdminView):
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

    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        return False


@admin.register(Parameter)
class ParameterAdminView(CustomAdminView):
    inlines = [PluginConfigInlineForParameter]
    search_fields = ["name"]
    list_filter = ["is_secret"]
    list_display = ParameterInlineForm.Meta.fields
    fields = list_display


@admin.register(PythonModule)
class PythonModuleAdminView(CustomAdminView):
    list_display = [
        "module",
        "base_path",
        "get_parameters",
        "get_secrets",
        "update_schedule",
        "health_check_schedule",
    ]
    search_fields = ["module", "base_path"]
    list_filter = ["base_path"]
    inlines = [ParameterInline]

    @admin.display(description="Parameters")
    def get_parameters(self, obj: PythonModule):
        return list(obj.parameters.filter(is_secret=False).order_by("-name"))

    @admin.display(description="Secrets")
    def get_secrets(self, obj: PythonModule):
        return list(obj.parameters.filter(is_secret=True).order_by("-name"))


class AbstractConfigAdminView(CustomAdminView):
    list_display = ("name", "description", "disabled", "disabled_in_orgs")
    search_fields = ("name",)
    list_filter = ("disabled",)
    # allow to clone the object
    save_as = True

    @admin.display(description="Disabled in orgs")
    def disabled_in_orgs(self, instance: AbstractConfig):
        return list(
            instance.orgs_configuration.filter(disabled=True).values_list(
                "organization__name", flat=True
            )
        )


class PythonConfigAdminView(AbstractConfigAdminView):
    list_display = AbstractConfigAdminView.list_display + ("routing_key",)
    inlines = [PluginConfigInlineForPythonConfig, OrganizationPluginConfigurationInLine]
    list_filter = ["routing_key"]


@admin.register(OrganizationPluginConfiguration)
class OrganizationPluginConfigurationAdminView(CustomAdminView):
    list_display = [
        "config",
        "organization",
        "disabled",
        "disabled_comment",
        "rate_limit_timeout",
    ]
    exclude = ["content_type", "object_id"]
    list_filter = ["organization", "content_type"]
    form = OrganizationPluginConfigurationForm
