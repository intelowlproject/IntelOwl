from django import forms

from api_app.models import Parameter


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
