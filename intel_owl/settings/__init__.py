# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# flake8: noqa

# Tests
TEST_RUNNER = "intel_owl.test_runner.MyTestRunner"

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
    # admin
    "prettyjson",
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
    "authentication",
    "api_app",
    "api_app.analyzers_manager",
    "api_app.connectors_manager",
    "api_app.visualizers_manager",
    "api_app.playbooks_manager",
    # auth
    "rest_email_auth",
    "drf_recaptcha",
    # performance debugging
    "silk",
    # two-factor-auth
    "django_otp",
    "django_otp.plugins.otp_static",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_email",  # <- if you want email capability.
    "two_factor",
    "two_factor.plugins.phonenumber",  # <- if you want phone number capability.
    "two_factor.plugins.email",  # <- if you want email capability.
]

LOGIN_URL = "two_factor:login"
LOGIN_REDIRECT_URL = "/"

from .auth import *  # lgtm [py/polluting-import]
from .aws import *  # lgtm [py/polluting-import]
from .cache import *  # lgtm [py/polluting-import]

# inject from other modules
from .celery import *  # lgtm [py/polluting-import]
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
