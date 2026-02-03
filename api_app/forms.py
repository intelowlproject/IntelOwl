from django import forms
from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import OrganizationPluginConfiguration, Parameter
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig


class MultilineJSONField(forms.JSONField):
    """
    A custom JSONField that handles multiline JSON input.

    This field processes multiline input by replacing newline characters
    with the escape sequence '\\n', and also removes carriage returns and
    double quotes.

    Methods:
        _cleaning_and_multiline(value): Static method to process the multiline input.
        to_python(value): Converts the input value to its Python representation.
        has_changed(initial, data): Checks if the field's data has changed from its initial value.
        bound_data(data, initial): Returns the data bound to the form field.
    """

    @staticmethod
    def _cleaning_and_multiline(value):
        """
        Process multiline input to escape newline characters and remove carriage returns and quotes.

        Args:
            value (str): The input value to process.

        Returns:
            str: The processed value.
        """
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
        """
        Converts the input value to its Python representation after processing it.

        Args:
            value (str): The input value.

        Returns:
            any: The Python representation of the input value.
        """
        return super().to_python(self._cleaning_and_multiline(value))

    def has_changed(self, initial, data):
        """
        Checks if the field's data has changed from its initial value after processing.

        Args:
            initial (any): The initial value of the field.
            data (any): The current value of the field.

        Returns:
            bool: True if the field's data has changed, False otherwise.
        """
        return super().has_changed(initial, self._cleaning_and_multiline(data))

    def bound_data(self, data, initial):
        """
        Returns the data bound to the form field after processing.

        Args:
            data (any): The current value of the field.
            initial (any): The initial value of the field.

        Returns:
            any: The processed data bound to the field.
        """
        return super().bound_data(self._cleaning_and_multiline(data), initial)


class ParameterInlineForm(forms.ModelForm):
    """
    A form for the Parameter model that uses the custom MultilineJSONField for the 'default' field.

    Attributes:
        default (MultilineJSONField): The default value for the parameter, processed for multiline JSON input.
    """

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
    """
    A form for the OrganizationPluginConfiguration model, allowing configuration of various plugins.

    Attributes:
        analyzer (ModelChoiceField): Field for selecting an AnalyzerConfig.
        connector (ModelChoiceField): Field for selecting a ConnectorConfig.
        visualizer (ModelChoiceField): Field for selecting a VisualizerConfig.
        pivot (ModelChoiceField): Field for selecting a PivotConfig.
        playbook (ModelChoiceField): Field for selecting a PlaybookConfig.
        _plugins (list): List of plugin fields.
    """

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
        """
        Validates that exactly one plugin configuration is selected.

        Raises:
            ValidationError: If not exactly one configuration is selected.
        """
        number_plugins = sum(bool(self.cleaned_data.get(val, False)) for val in self._plugins)
        if number_plugins != 1 and not self.instance.pk:
            self.add_error(
                field=None,
                error={field: "You must select exactly one configuration" for field in self._plugins},
            )
        return super().validate_unique()

    def save(self, commit=True):
        """
        Saves the form instance, ensuring that exactly one plugin configuration is set.

        Args:
            commit (bool): Whether to commit the save to the database.

        Returns:
            OrganizationPluginConfiguration: The saved instance.

        Raises:
            ValidationError: If no configuration is set when saving a new instance.
        """
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
