from django.conf import settings


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
    return instance.md5
