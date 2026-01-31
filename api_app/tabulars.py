from typing import Optional

from django.contrib import admin
from django.contrib.contenttypes.admin import GenericTabularInline

from api_app.forms import ParameterInlineForm
from api_app.models import (
    OrganizationPluginConfiguration,
    Parameter,
    PluginConfig,
    PythonConfig,
)


class PluginConfigInlineForParameter(admin.TabularInline):
    """
    Inline admin class for displaying and editing PluginConfig instances
    related to a specific Parameter in a tabular form.
    """

    model = PluginConfig
    extra = 0
    fields = ["value"]


class PluginConfigInlineForPythonConfig(admin.TabularInline):
    """
    Inline admin class for displaying and editing PluginConfig instances
    related to a specific PythonConfig in a tabular form.
    """

    model = PluginConfig
    extra = 0
    fields = ["parameter", "is_secret", "get_type", "value"]
    readonly_fields = ["is_secret", "get_type"]
    verbose_name = "Default Plugin Config"
    verbose_name_plural = "Default Plugin Configs"

    @admin.display(description="Type")
    def get_type(self, instance: PluginConfig):
        return instance.parameter.type

    @staticmethod
    def has_delete_permission(request, obj=None):
        return False

    @staticmethod
    def get_parent_pk(request) -> Optional[str]:
        parent_pk = request.resolver_match.kwargs.get("object_id")
        if parent_pk:
            # django encode the url this way when it finds a `_`
            parent_pk = parent_pk.replace("_5F", "_")
            return parent_pk

    def get_parent(self, request) -> Optional[PythonConfig]:
        parent_pk = self.get_parent_pk(request)
        if parent_pk:
            plugin_config = self.parent_model.objects.get(pk=parent_pk)
            return plugin_config

    def formfield_for_foreignkey(self, db_field, request=None, **kwargs):
        field = super().formfield_for_foreignkey(db_field, request, **kwargs)

        if db_field.name == "parameter":
            parent_model = self.get_parent(request)
            # we are creating an object
            if parent_model is None:
                return field
            # the user should add the default for parameters, not secrets
            field.queryset = field.queryset.filter(python_module=parent_model.python_module, is_secret=False)
        return field

    def get_extra(self, request, obj: PluginConfig = None, **kwargs):
        if self.get_parent(request):
            return (
                Parameter.objects.filter(
                    python_module=self.get_parent(request).python_module,
                    is_secret=False,
                ).count()
                - PluginConfig.objects.filter(
                    **{self.get_parent(request).snake_case_name.lower(): self.get_parent_pk(request)},
                    owner=None,
                    for_organization=False,
                    parameter__is_secret=False,
                ).count()
            )
        return 0

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .filter(owner=None, for_organization=False, parameter__is_secret=False)
        )

    @admin.display(description="Is a secret", boolean=True)
    def is_secret(self, instance: PluginConfig):
        return instance.parameter.is_secret


class ParameterInline(admin.TabularInline):
    """
    Inline admin class for displaying and editing Parameter instances in a tabular form.
    """

    model = Parameter
    list_display = ParameterInlineForm.Meta.fields
    fields = list_display
    show_change_link = True

    @staticmethod
    def get_extra(request, obj: Parameter = None, **kwargs):
        return 0


class OrganizationPluginConfigurationInLine(GenericTabularInline):
    """
    Inline admin class for displaying and editing OrganizationPluginConfiguration
    instances in a generic tabular form.
    """

    model = OrganizationPluginConfiguration
    list_display = [
        "organization",
        "rate_limit_timeout",
        "disabled",
        "disabled_comment",
    ]
    fields = list_display
    show_change_link = True

    @staticmethod
    def get_extra(request, obj: OrganizationPluginConfiguration = None, **kwargs):
        return 0
