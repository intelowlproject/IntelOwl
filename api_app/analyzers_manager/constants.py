# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models


class TypeChoices(models.TextChoices):
    FILE = "file"
    OBSERVABLE = "observable"


class HashChoices(models.TextChoices):
    MD5 = "md5"
    SHA256 = "sha256"


class ObservableTypes(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"

class AllTypes(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"
    FILE = "file"
