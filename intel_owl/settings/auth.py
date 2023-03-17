# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# flake8: noqa

# this is better to be run after commons.py

import os

from intel_owl import secrets

AUTH_USER_MODEL = "certego_saas_user.User"  # custom user model

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
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

LDAP_ENABLED = os.environ.get("LDAP_ENABLED", False) == "True"
RADIUS_AUTH_ENABLED = os.environ.get("RADIUS_AUTH_ENABLED", False) == "True"
if LDAP_ENABLED:
    from configuration.ldap_config import *  # lgtm [py/polluting-import] skipcq PYL-W0614

    AUTHENTICATION_BACKENDS.append("django_auth_ldap.backend.LDAPBackend")
if RADIUS_AUTH_ENABLED:
    from configuration.radius_config import *  # lgtm [py/polluting-import] skipcq PYL-W0614

    AUTHENTICATION_BACKENDS.append("intel_owl.backends.CustomRADIUSBackend")

AUTHLIB_OAUTH_CLIENTS = {}

if (
    secrets.get_secret("GOOGLE_CLIENT_ID")
    and str(secrets.get_secret("GOOGLE_CLIENT_ID")).endswith(
        ".apps.googleusercontent.com"
    )
    and secrets.get_secret("GOOGLE_CLIENT_SECRET")
):
    AUTHLIB_OAUTH_CLIENTS["google"] = {
        "client_id": secrets.get_secret("GOOGLE_CLIENT_ID"),
        "client_secret": secrets.get_secret("GOOGLE_CLIENT_SECRET"),
    }
