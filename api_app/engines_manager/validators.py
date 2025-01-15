from django.conf import settings
import os

from django.utils.module_loading import import_string
from pydantic import ValidationError


def validate_engine_module(value):
    path = ".".join([settings.BASE_ENGINE_MODULES_PYTHON_PATH, value])
    try:
        import_string(path)
    except ImportError:
        raise ValidationError(f"Path {path} does not exist")