# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models


class ScanMode(models.IntegerChoices):
    FORCE_NEW_ANALYSIS = 1
    CHECK_PREVIOUS_ANALYSIS = 2


class ReportStatus(models.TextChoices):
    FAILED = "FAILED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    KILLED = "KILLED"


class ParamTypes(models.TextChoices):
    INT = "int"
    FLOAT = "float"
    STR = "str"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
