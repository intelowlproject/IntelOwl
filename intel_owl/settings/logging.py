from intel_owl import secrets

from .commons import DEBUG

DISABLE_LOGGING_TEST = secrets.get_secret("DISABLE_LOGGING_TEST", False) == "True"
DJANGO_LOG_DIRECTORY = "/var/log/intel_owl/django"
INFO_OR_DEBUG_LEVEL = "DEBUG" if DEBUG else "INFO"
LOG_MSG_FORMAT = "%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "stdfmt": {
            "format": LOG_MSG_FORMAT,
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
        "certego_saas": {
            "level": INFO_OR_DEBUG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": f"{DJANGO_LOG_DIRECTORY}/api_app.log",
            "formatter": "stdfmt",
            "maxBytes": 20 * 1024 * 1024,
            "backupCount": 6,
        },
        "certego_saas_errors": {
            "level": INFO_OR_DEBUG_LEVEL,
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
        "certego_saas": {
            "handlers": ["certego_saas", "certego_saas_errors"],
            "level": INFO_OR_DEBUG_LEVEL,
            "propagate": True,
        },
    },
}
