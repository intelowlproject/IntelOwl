# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import sys

from intel_owl import secrets

# AWS settings
AWS_IAM_ACCESS = secrets.get_secret("AWS_IAM_ACCESS", False) == "True"
if not AWS_IAM_ACCESS:
    AWS_ACCESS_KEY_ID = secrets.get_secret("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = secrets.get_secret("AWS_SECRET_ACCESS_KEY")

AWS_REGION = secrets.get_secret("AWS_REGION", "eu-central-1")
AWS_USER_NUMBER = secrets.get_secret("AWS_USER_NUMBER")

AWS_SECRETS = secrets.get_secret("AWS_SECRETS", False) == "True"

AWS_SQS = secrets.get_secret("AWS_SQS", False) == "True"
if AWS_SQS:
    if not AWS_USER_NUMBER:
        print("you must specify the USER NUMBER")
        sys.exit(4)
    BROKER_URL = "sqs://"
