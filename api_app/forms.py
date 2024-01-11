from itertools import chain
from typing import Type

from django import forms

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Parameter, OrganizationPluginConfiguration, AbstractConfig


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
    _config: Type[AbstractConfig]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["configuration"] = forms.ModelChoiceField(
            queryset=self._config.objects.filter(orgs_configuration__isnull=True)
    )


    def save(self, commit=True):
        config = self.cleaned_data.get('configuration', None)
        instance = super().save(commit=False)
        instance.config = config
        if commit:
            instance.save()
        return instance

    class Meta:
        model = OrganizationPluginConfiguration
        fields = [
            "disabled", "disabled_comment", "organization", "rate_limit_timeout"
        ]