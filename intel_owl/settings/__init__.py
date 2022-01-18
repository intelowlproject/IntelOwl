# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# flake8: noqa
import os

from intel_owl import secrets

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
    "certego_saas.apps.notifications",
    "certego_saas.apps.organization",
    # intelowl apps
    "api_app",
    "api_app.analyzers_manager",
    "api_app.connectors_manager",
]


# inject from other modules
from .cache import *
from .certego import *
from .commons import *
from .db import *
from .django import *
from .elasticsearch import *
from .logging import *
from .mail import *
from .rest import *
from .security import *
from .storage import *

BROKER_URL = secrets.get_secret("BROKER_URL", "amqp://guest:guest@rabbitmq:5672")
RESULT_BACKEND = "django-db"
CELERY_QUEUES = secrets.get_secret("CELERY_QUEUES", "default").split(",")

# AWS
AWS_SECRETS = secrets.get_secret("AWS_SECRETS", False) == "True"
AWS_SQS = secrets.get_secret("AWS_SQS", False) == "True"

# Auth backends
LDAP_ENABLED = os.environ.get("LDAP_ENABLED", False) == "True"
if LDAP_ENABLED:
    from configuration.ldap_config import *  # lgtm [py/polluting-import]

    AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")
