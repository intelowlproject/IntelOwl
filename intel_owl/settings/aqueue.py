# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# this module must run before the others

from ._util import get_secret

BROKER_URL = get_secret("BROKER_URL", "amqp://guest:guest@rabbitmq:5672")
RESULT_BACKEND = "django-db"
CELERY_QUEUES = get_secret("CELERY_QUEUES", "default").split(",")
