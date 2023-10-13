# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# this module must run before the others
import sys

from ._util import get_secret
from .aws import AWS_SQS, AWS_USER_NUMBER
RESULT_BACKEND = "django-db"
BROKER_URL = get_secret(
    "BROKER_URL", "sqs://" if AWS_SQS else "amqp://guest:guest@rabbitmq:5672"
)
DEFAULT_QUEUE = "default"
BROADCAST_QUEUE = "broadcast"
CONFIG_QUEUE = "config"

CELERY_QUEUES = get_secret("CELERY_QUEUES", DEFAULT_QUEUE).split(",")

if CONFIG_QUEUE not in CELERY_QUEUES:
    CELERY_QUEUES.append(CONFIG_QUEUE)

if AWS_SQS and not AWS_USER_NUMBER:
    print("you must specify the USER NUMBER")
    sys.exit(4)
