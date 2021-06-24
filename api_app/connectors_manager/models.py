# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import models
from django.contrib.postgres import fields as postgres_fields

from enum import Enum


class Statuses(Enum):
    FAILED = 0
    PENDING = 1
    RUNNING = 2
    SUCCESS = 3


class ConnectorReport(models.Model):
    Statuses = Statuses

    connector = models.CharField(max_length=128, unique=True)
    job = models.ForeignKey(
        "api_app.Job", related_name="connector_reports", on_delete=models.CASCADE
    )
    status = models.CharField(
        max_length=50, choices=[(s.name, s.name) for s in Statuses]
    )
    report = models.JSONField(default=dict)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512), default=list, blank=True
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def __str__(self):
        return f"Connector({self.connector})-{self.job}"

    @property
    def process_time(self):
        return self.end_time - self.start_time
