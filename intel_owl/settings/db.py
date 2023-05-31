# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Database Conf

import sys

from intel_owl import secrets

from .aws import AWS_RDS_IAM_ROLE, AWS_REGION

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

PG_DB = secrets.get_secret("DB_NAME", "intel_owl_db")
PG_HOST = secrets.get_secret("DB_HOST")
PG_PORT = secrets.get_secret("DB_PORT")
PG_USER = secrets.get_secret("DB_USER")
PG_PASSWORD = secrets.get_secret("DB_PASSWORD")
PG_SSL = secrets.get_secret("DB_SSL", False) == "True"
PG_ENGINE = "django.db.backends.postgresql"
if AWS_RDS_IAM_ROLE:
    if PG_PASSWORD:
        print(
            "you specified both a DB password and that you want to use"
            " IAM roles for authentication. Choose one"
        )
        sys.exit(3)
    # SSL is mandatory for AWS RDS
    PG_SSL = True
    PG_ENGINE = "django_iam_dbauth.aws.postgresql"

DATABASES = {
    "default": {
        "ENGINE": PG_ENGINE,
        "NAME": PG_DB,
        "HOST": PG_HOST,
        "PORT": PG_PORT,
        "USER": PG_USER,
        "OPTIONS": {},
        "TIMEOUT": 180,
        "CONN_MAX_AGE": 3600,
        "CONN_HEALTH_CHECKS": True,
    },
}

if AWS_RDS_IAM_ROLE:
    DATABASES["default"]["OPTIONS"]["use_iam_auth"] = True
    DATABASES["default"]["OPTIONS"]["region_name"] = AWS_REGION
else:
    DATABASES["default"]["PASSWORD"] = PG_PASSWORD
if PG_SSL:
    DATABASES["default"]["OPTIONS"]["sslmode"] = "require"
