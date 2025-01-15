from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.module_loading import import_string


def validate_engine_module(value):
    path = f"{settings.BASE_ENGINE_MODULES_PYTHON_PATH}.{value}"
    try:
        import_string(path)
    except ImportError:
        raise ValidationError(f"Path {path} does not exist")
