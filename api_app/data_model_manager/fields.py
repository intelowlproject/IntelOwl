from typing import Any

from django.contrib.postgres.fields import ArrayField
from django.db import models


class SetField(ArrayField):
    def to_python(self, value):
        result = super().to_python(value)
        return list(set(result))


class LowercaseCharField(models.CharField):
    def to_python(self, value: Any):
        result = super().to_python(value)
        if result and isinstance(result, str):
            return result.lower()
        return result
