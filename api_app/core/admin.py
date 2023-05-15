# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django import forms
from django.contrib import admin
from django.db.models import JSONField
from prettyjson import PrettyJSONWidget

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
    list_display = ("name", "type", "description", "is_secret", "required")
    fields = list_display


class ParameterInlineForm(forms.ModelForm):
    default = forms.JSONField(required=False)

    class Meta:
        model = Parameter
        fields = ParameterAdminView.fields

    def __init__(self, *args, **kwargs):
        instance: Parameter = kwargs.get("instance", None)
        if instance:
            try:
                default = PluginConfig.objects.get(
                    parameter=instance, owner__isnull=True
                )
            except PluginConfig.DoesNotExist:
                default = None
            kwargs["initial"] = {"default": default}
        super().__init__(*args, **kwargs)

    def save(self, commit: bool = ...):
        instance = super().save(commit=commit)
        if self.cleaned_data["default"] is not None:
            pc = PluginConfig(
                value=self.cleaned_data["default"],
                owner=None,
                for_organization=False,
                parameter=instance,
            )
            pc.full_clean()
            pc.save()

        return instance


class ParameterInline(admin.TabularInline):
    model = Parameter
    list_display = ParameterAdminView.list_display
    fields = list_display + ("default",)
    extra = 0
    show_change_link = True
    form = ParameterInlineForm


class AbstractConfigAdminView(JsonViewerAdminView):
    inlines = [ParameterInline]
    list_display = (
        "name",
        "python_module",
        "params",
        "secrets",
        "disabled",
        "disabled_in_orgs",
    )
    search_fields = ("name",)
    # allow to clone the object
    save_as = True

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

    @staticmethod
    def disabled_in_orgs(instance: AbstractConfig):
        return [org.name for org in instance.disabled_in_organizations.all()]
