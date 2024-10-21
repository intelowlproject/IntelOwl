# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from intel_owl import secrets

# this must be first because the function get_secretes depends from it
AWS_REGION = secrets.get_secret("AWS_REGION", "eu-central-1")
