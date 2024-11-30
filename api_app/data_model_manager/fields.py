from typing import Any

from django.db import models


class LowercaseCharField(models.CharField):

    def to_python(self, value: Any):
        result = super().to_python(value)
        if result and isinstance(result, str):
            return result.lower()
        return result
