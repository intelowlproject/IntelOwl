from django.conf import settings
from django.utils import timezone


def config_default():
    return dict(queue=settings.DEFAULT_QUEUE, soft_time_limit=60)


def default_runtime():
    return {
        "analyzers": {},
        "connectors": {},
        "pivots": {},
        "visualizers": {},
    }


def file_directory_path(instance, filename):
    now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"job_{now}_{filename}"
