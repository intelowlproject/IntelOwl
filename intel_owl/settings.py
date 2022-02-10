# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# flake8: noqa
import os
from datetime import timedelta

from django.core.files.storage import FileSystemStorage
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
TEST_MODE = MOCK_CONNECTIONS
LDAP_ENABLED = os.environ.get("LDAP_ENABLED", False) == "True"
RADIUS_AUTH_ENABLED = os.environ.get("RADIUS_AUTH_ENABLED", False) == "True"
LOCAL_STORAGE = os.environ.get("LOCAL_STORAGE", "True") == "True"
# Storage settings
if LOCAL_STORAGE:

    class FileSystemStorageWrapper(FileSystemStorage):
        def retrieve(self, file, analyzer):
            # we have one single sample for every analyzer
            return file.path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.FileSystemStorageWrapper"
else:
    from storages.backends.s3boto3 import S3Boto3Storage

    class S3Boto3StorageWrapper(S3Boto3Storage):
        def retrieve(self, file, analyzer):
            # FIXME we can optimize this a lot.
            #  Right now we are doing an http request FOR analyzer. We can have a
            #  proxy that will store the content and then save it locally

            # The idea is to download the file in MEDIA_ROOT/analyzer/namefile if it does not exist
            path_dir = os.path.join(MEDIA_ROOT, analyzer)
            name = file.name
            _path = os.path.join(path_dir, name)
            if not os.path.exists(_path):
                os.makedirs(path_dir, exist_ok=True)
                if not self.exists(name):
                    raise AssertionError
                with self.open(name) as s3_file_object:
                    content = s3_file_object.read()
                    s3_file_object.seek(0)
                    with open(_path, "wb") as local_file_object:
                        local_file_object.write(content)
            return _path

    DEFAULT_FILE_STORAGE = "intel_owl.settings.S3Boto3StorageWrapper"
    AWS_STORAGE_BUCKET_NAME = secrets.get_secret("AWS_STORAGE_BUCKET_NAME")

# AWS settings
AWS_IAM_ACCESS = os.environ.get("AWS_IAM_ACCESS", False) == "True"
if not AWS_IAM_ACCESS:
    AWS_ACCESS_KEY_ID = secrets.get_secret("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = secrets.get_secret("AWS_SECRET_ACCESS_KEY")

# used for generating links to web client e.g. job results page
WEB_CLIENT_DOMAIN = secrets.get_secret("INTELOWL_WEB_CLIENT_DOMAIN")

# Security Stuff
HTTPS_ENABLED = os.environ.get("HTTPS_ENABLED", "not_enabled")
if HTTPS_ENABLED == "enabled":
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    WEB_CLIENT_URL = f"https://{WEB_CLIENT_DOMAIN}"
else:
    WEB_CLIENT_URL = f"http://{WEB_CLIENT_DOMAIN}"

SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True
ALLOWED_HOSTS = ["*"]

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
    # DRF
    "rest_framework",
    "durin",
    "guardian",
    "drf_spectacular",
    # intelowl apps
    "api_app.apps.ApiAppConfig",
    "api_app.analyzers_manager.apps.AnalyzersManagerConfig",
    "api_app.connectors_manager.apps.ConnectorsManagerConfig",
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
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# DRF Spectacular
SPECTACULAR_SETTINGS = {
    "TITLE": "IntelOwl API specification",
    "VERSION": "3.2.4",
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

# DATABASE CONF
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

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

BROKER_URL = secrets.get_secret("BROKER_URL", "amqp://guest:guest@rabbitmq:5672")
RESULT_BACKEND = "django-db"
CELERY_QUEUES = os.environ.get("CELERY_QUEUES", "default").split(",")

# AWS
AWS_SECRETS = os.environ.get("AWS_SECRETS", False) == "True"
AWS_SQS = os.environ.get("AWS_SQS", False) == "True"

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

if RADIUS_AUTH_ENABLED:
    from configuration.radius_config import *  # lgtm [py/polluting-import]

    AUTHENTICATION_BACKENDS.append("intel_owl.backends.CustomRADIUSBackend")

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
        # 500 errors are handled by this in the same log file of the others API errors
        "django_unhandled_errors": {
            "level": "ERROR",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api_app_errors.log",
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
        "django": {
            "handlers": ["django_unhandled_errors"],
            "level": "ERROR",
            "propagate": True,
        },
    },
}
