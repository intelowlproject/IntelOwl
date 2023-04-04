# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django import forms
from django.contrib.postgres.fields import ArrayField


class ChoiceArrayField(ArrayField):
    def formfield(self, **kwargs):
        defaults = {
            "form_class": forms.TypedMultipleChoiceField,
            "choices": self.base_field.choices,
            "coerce": self.base_field.to_python,
            "widget": forms.CheckboxSelectMultiple,
        }
        defaults.update(kwargs)
        # this super call parameter is required
        return super(ArrayField, self).formfield(**defaults)
