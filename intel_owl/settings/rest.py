# flake8: noqa E501

from datetime import timedelta

from .commons import VERSION

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    # Auth
    "DEFAULT_AUTHENTICATION_CLASSES": ["durin.auth.CachedTokenAuthentication"],
    # Pagination
    "DEFAULT_PAGINATION_CLASS": "certego_saas.ext.pagination.CustomPageNumberPagination",
    "PAGE_SIZE": 10,
    # Permission
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    # Exception Handling
    "EXCEPTION_HANDLER": "certego_saas.ext.exceptions.custom_exception_handler",
    # Filter
    "DEFAULT_FILTER_BACKENDS": [
        "rest_framework_filters.backends.RestFrameworkFilterBackend",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

# Django-Rest-Durin
REST_DURIN = {
    "DEFAULT_TOKEN_TTL": timedelta(days=31),
    "TOKEN_CHARACTER_LENGTH": 32,
    "USER_SERIALIZER": "certego_saas.user.serializers.UserSerializer",
    "AUTH_HEADER_PREFIX": "Token",
    "TOKEN_CACHE_TIMEOUT": 300,  # 5 minutes
    "REFRESH_TOKEN_ON_LOGIN": True,
    "API_ACCESS_CLIENT_NAME": "PyIntelOwl",
    "API_ACCESS_EXCLUDE_FROM_SESSIONS": True,
    "API_ACCESS_RESPONSE_INCLUDE_TOKEN": True,
    # not part of durin but used in data migration
    "API_ACCESS_CLIENT_TOKEN_TTL": timedelta(days=365),
}

# drf-spectacular
SPECTACULAR_SETTINGS = {
    "TITLE": "IntelOwl API specification",
    "VERSION": VERSION,
}

# drf-recaptcha (not used in IntelOwl but required by certego-saas pkg)
DRF_RECAPTCHA_SECRET_KEY = ""
DRF_RECAPTCHA_TESTING = True
DRF_RECAPTCHA_TESTING_PASS = True
