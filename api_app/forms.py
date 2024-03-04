from django import forms
from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import OrganizationPluginConfiguration, Parameter
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig


class MultilineJSONField(forms.JSONField):
    @staticmethod
    def _cleaning_and_multiline(value):
        if value is not None and "\n" in value:
            cleaned_value = []
            for line in value.splitlines():
                line.replace("\r", "")
                line.replace('"', "")
                line = line + "\\n"
                cleaned_value.append(line)
            value = '"' + "".join(cleaned_value) + '"'
        return value

    def to_python(self, value):
        return super().to_python(self._cleaning_and_multiline(value))

    def has_changed(self, initial, data):
        return super().has_changed(initial, self._cleaning_and_multiline(data))

    def bound_data(self, data, initial):
        return super().bound_data(self._cleaning_and_multiline(data), initial)


class ParameterInlineForm(forms.ModelForm):
    default = MultilineJSONField(required=False)

    class Meta:
        model = Parameter
        fields = [
            "name",
            "type",
            "description",
            "is_secret",
            "required",
            "python_module",
        ]


class OrganizationPluginConfigurationForm(forms.ModelForm):
    analyzer = forms.ModelChoiceField(
        queryset=AnalyzerConfig.objects.filter(orgs_configuration__isnull=True),
        required=False,
    )
    connector = forms.ModelChoiceField(
        queryset=ConnectorConfig.objects.filter(orgs_configuration__isnull=True),
        required=False,
    )

    visualizer = forms.ModelChoiceField(
        queryset=VisualizerConfig.objects.filter(orgs_configuration__isnull=True),
        required=False,
    )
    pivot = forms.ModelChoiceField(
        queryset=PivotConfig.objects.filter(orgs_configuration__isnull=True),
        required=False,
    )
    playbook = forms.ModelChoiceField(
        queryset=PlaybookConfig.objects.filter(orgs_configuration__isnull=True),
        required=False,
    )
    _plugins = ["analyzer", "connector", "visualizer", "pivot", "playbook"]

    def validate_unique(self) -> None:
        number_plugins = sum(
            bool(self.cleaned_data.get(val, False)) for val in self._plugins
        )
        if number_plugins != 1 and not self.instance.pk:
            self.add_error(
                field=None,
                error={
                    field: "You must select exactly one configuration"
                    for field in self._plugins
                },
            )
        return super().validate_unique()

    def save(self, commit=True):
        if not self.instance.pk:
            for field in self._plugins:
                config = self.cleaned_data.get(field, None)
                if config:
                    break
            else:
                raise ValidationError("Config is required")
            instance = super().save(commit=False)
            instance.config = config
        else:
            instance = super().save(commit=False)
        if commit:
            instance.save()
        return instance

    class Meta:
        model = OrganizationPluginConfiguration
        fields = ["disabled", "disabled_comment", "organization", "rate_limit_timeout"]
