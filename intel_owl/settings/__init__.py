# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# flake8: noqa

from intel_owl import secrets

# Tests
TEST_RUNNER = "intel_owl.test_runner.MyTestRunner"

# AWS settings
AWS_IAM_ACCESS = secrets.get_secret("AWS_IAM_ACCESS", False) == "True"
if not AWS_IAM_ACCESS:
    AWS_ACCESS_KEY_ID = secrets.get_secret("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = secrets.get_secret("AWS_SECRET_ACCESS_KEY")

# Application definition
INSTALLED_APPS = [
    # default
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    # celery, elasticsearch
    "django_celery_results",
    "django_elasticsearch_dsl",
    # rest framework libs
    "rest_framework",
    "rest_framework_filters",
    "drf_spectacular",
    # certego libs
    "durin",
    "certego_saas",
    "certego_saas.apps.user",
    "certego_saas.apps.notifications",
    "certego_saas.apps.organization",
    # intelowl apps
    "api_app",
    "authentication",
    "api_app.analyzers_manager",
    "api_app.connectors_manager",
    "api_app.playbooks_manager",
]

# inject from other modules
from .auth import *  # lgtm [py/polluting-import]
from .cache import *  # lgtm [py/polluting-import]
from .certego import *  # lgtm [py/polluting-import]
from .commons import *  # lgtm [py/polluting-import]
from .db import *  # lgtm [py/polluting-import]
from .django import *  # lgtm [py/polluting-import]
from .elasticsearch import *  # lgtm [py/polluting-import]
from .logging import *  # lgtm [py/polluting-import]
from .mail import *  # lgtm [py/polluting-import]
from .rest import *  # lgtm [py/polluting-import]
from .security import *  # lgtm [py/polluting-import]
from .storage import *  # lgtm [py/polluting-import]

BROKER_URL = secrets.get_secret("BROKER_URL", "amqp://guest:guest@rabbitmq:5672")
RESULT_BACKEND = "django-db"
CELERY_QUEUES = secrets.get_secret("CELERY_QUEUES", "default").split(",")

# AWS
AWS_SECRETS = secrets.get_secret("AWS_SECRETS", False) == "True"
AWS_SQS = secrets.get_secret("AWS_SQS", False) == "True"
