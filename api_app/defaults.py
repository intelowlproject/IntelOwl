from django.utils import timezone

from intel_owl.celery import DEFAULT_QUEUE


def config_default():
    return dict(queue=DEFAULT_QUEUE, soft_time_limit=60)


def default_runtime():
    return {
        "analyzers": {},
        "connectors": {},
        "visualizers": {},
    }


def file_directory_path(instance, filename):
    now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"job_{now}_{filename}"
