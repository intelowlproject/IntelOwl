# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models
from django.contrib.postgres import fields as pg_fields

from enum import Enum


class Statuses(Enum):
    FAILED = 0
    PENDING = 1
    RUNNING = 2
    SUCCESS = 3


class AbstractReport(models.Model):
    # constants
    Statuses = Statuses

    # fields
    status = models.CharField(
        max_length=50, choices=[(s.name, s.name) for s in Statuses]
    )
    report = models.JSONField(default=dict)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=512), default=list, blank=True
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    # meta
    class Meta:
        abstract = True

    # properties
    @property
    def process_time(self):
        return self.end_time - self.start_time
