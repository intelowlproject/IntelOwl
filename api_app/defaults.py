from intel_owl.celery import DEFAULT_QUEUE


def config_default():
    return dict(queue=DEFAULT_QUEUE, soft_time_limit=60)
