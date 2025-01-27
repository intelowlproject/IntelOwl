# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from logging import getLogger

from django.db import models

logger = getLogger(__name__)


class TypeChoices(models.TextChoices):
    FILE = "file"
    OBSERVABLE = "observable"


class HashChoices(models.TextChoices):
    MD5 = "md5"
    SHA256 = "sha256"


class HTTPMethods(models.TextChoices):
    GET = "get"
    POST = "post"
    PUT = "put"
    PATCH = "patch"
    DELETE = "delete"
