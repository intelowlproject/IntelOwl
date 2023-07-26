from django import forms

from api_app.core.models import Parameter
from api_app.models import PluginConfig


class MultilineJSONField(forms.JSONField):
    def _cleaning_and_multiline(self, value):
        if value is not None and "\n" in value:
            cleaned_value = []
            for line in value.splitlines():
                line.replace('\r', '')
                line.replace('\"', '')
                line = line + "\\n"
                cleaned_value.append(line)
            value = "\"" + "".join(cleaned_value) + "\""
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
        fields = ("name", "type", "description", "is_secret", "required")

    def __init__(self, *args, **kwargs):
        instance: Parameter = kwargs.get("instance")
        if instance:
            try:
                pc = PluginConfig.objects.get(parameter=instance, owner__isnull=True)
            except PluginConfig.DoesNotExist:
                default = None
            else:
                default = pc.value
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
