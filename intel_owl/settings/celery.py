# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# this module must run before the others
import sys

from ._util import get_secret
from .aws import AWS_SQS, AWS_USER_NUMBER

BROKER_URL = get_secret(
    "BROKER_URL", "sqs://" if AWS_SQS else "amqp://guest:guest@rabbitmq:5672"
)
RESULT_BACKEND = "django-db"
CELERY_QUEUES = get_secret("CELERY_QUEUES", "default").split(",")
BROADCAST_QUEUE = "broadcast"

if AWS_SQS and not AWS_USER_NUMBER:
    print("you must specify the USER NUMBER")
    sys.exit(4)
