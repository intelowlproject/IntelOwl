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

    def has_add_permission(self, request):
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
    default = forms.JSONField()

    class Meta:
        model = Parameter
        fields = ParameterAdminView.fields

    def save(self, commit: bool = ...):
        instance = super().save(commit=commit)
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
    extra = 1
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

    def params(self, instance: AbstractConfig):
        return list(
            instance.parameters.filter(is_secret=False).values_list("name", flat=True)
        )

    def secrets(self, instance: AbstractConfig):
        return list(
            instance.parameters.filter(is_secret=True).values_list("name", flat=True)
        )

    def disabled_in_orgs(self, instance: AbstractConfig):
        return [org.name for org in instance.disabled_in_organizations.all()]
