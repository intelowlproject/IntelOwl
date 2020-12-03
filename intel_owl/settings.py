# flake8: noqa
import os
from datetime import timedelta

from django.core.management.utils import get_random_secret_key

from intel_owl import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("DJANGO_SECRET", None) or get_random_secret_key()

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DEBUG", False) == "True"

DJANGO_LOG_DIRECTORY = "/var/log/intel_owl/django"
PROJECT_LOCATION = "/opt/deploy/intel_owl"
MEDIA_ROOT = "/opt/deploy/files_required"
DISABLE_LOGGING_TEST = os.environ.get("DISABLE_LOGGING_TEST", False) == "True"
MOCK_CONNECTIONS = os.environ.get("MOCK_CONNECTIONS", False) == "True"
LDAP_ENABLED = os.environ.get("LDAP_ENABLED", False) == "True"

# Security Stuff
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "not_enabled")
if HTTPS_ENABLED == "enabled":
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True

SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True
ALLOWED_HOSTS = ["*"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "memoize",
    "rest_framework",
    "durin",
    "guardian",
    "api_app.apps.ApiAppConfig",
    "django_elasticsearch_dsl",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "intel_owl.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "intel_owl.wsgi.application"

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "durin.auth.CachedTokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "EXCEPTION_HANDLER": "rest_framework.views.exception_handler",
}

# Django-Rest-Durin
REST_DURIN = {
    "DEFAULT_TOKEN_TTL": timedelta(days=14),
    "TOKEN_CHARACTER_LENGTH": 32,
    "USER_SERIALIZER": "durin.serializers.UserSerializer",
    "AUTH_HEADER_PREFIX": "Token",
    "TOKEN_CACHE_TIMEOUT": 300,  # 5 minutes
    "REFRESH_TOKEN_ON_LOGIN": True,
}

DB_HOST = secrets.get_secret("DB_HOST")
DB_PORT = secrets.get_secret("DB_PORT")
DB_NAME = os.environ.get("DB_NAME", "intel_owl_db")
DB_USER = secrets.get_secret("DB_USER")
DB_PASSWORD = secrets.get_secret("DB_PASSWORD")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
    },
}

# Elastic Search Configuration
if os.environ.get("ELASTICSEARCH_ENABLED", False) == "True":
    ELASTICSEARCH_DSL = {
        "default": {"hosts": os.environ.get("ELASTICSEARCH_HOST")},
    }
    ELASTICSEARCH_DSL_INDEX_SETTINGS = {
        "number_of_shards": int(os.environ.get("ELASTICSEARCH_NO_OF_SHARDS")),
        "number_of_replicas": int(os.environ.get("ELASTICSEARCH_NO_OF_REPLICAS")),
    }
else:
    ELASTICSEARCH_DSL_AUTOSYNC = False
    ELASTICSEARCH_DSL = {
        "default": {"hosts": ""},
    }

# CELERY STUFF
CELERY_BROKER_URL = secrets.get_secret("CELERY_BROKER_URL")
CELERY_ACCEPT_CONTENT = ["application/json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_IGNORE_RESULT = True
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "Europe/Rome"
CELERY_IMPORTS = ("intel_owl.tasks",)
CELERY_WORKER_REDIRECT_STDOUTS = False
CELERY_WORKER_HIJACK_ROOT_LOGGER = False
# these two are needed to enable priority and correct tasks execution
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_QUEUES = os.environ.get("CELERY_QUEUES", "default").split(",")
# this is to avoid RAM issues caused by long usage of this tool
CELERY_WORKER_MAX_TASKS_PER_CHILD = 200
# value is in kilobytes
CELERY_WORKER_MAX_MEMORY_PER_CHILD = 4000

AWS_SQS = os.environ.get("AWS_SQS", False) == "True"
if AWS_SQS:
    # this is for AWS SQS support
    CELERY_BROKER_TRANSPORT_OPTIONS = {
        "region": "eu-central-1",
        "polling_interval": 1,
        "visibility_timeout": 3600,
        "wait_time_seconds": 20,
    }

# Django Guardian
GUARDIAN_RAISE_403 = True

# Auth backends
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
]
if LDAP_ENABLED:
    from configuration.ldap_config import *  # lgtm [py/polluting-import]

    AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")

# Password validation

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static/")

STATICFILES_DIRS = (os.path.join(BASE_DIR, "static_intel/"),)

INFO_OR_DEBUG_LEVEL = "DEBUG" if DEBUG else "INFO"
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "stdfmt": {
            "format": "%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s",
        },
    },
    "handlers": {
        "api_app": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api_app.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
        "api_app_error": {
            "level": "ERROR",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api_app_errors.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
        "celery": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/celery.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
        "celery_error": {
            "level": "ERROR",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/celery_errors.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
        "django_auth_ldap": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/django_auth_ldap.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
    },
    "loggers": {
        "api_app": {
            "handlers": ["api_app", "api_app_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "celery": {
            "handlers": ["celery", "celery_error"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
        "django_auth_ldap": {
            "handlers": ["django_auth_ldap"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
    },
}
