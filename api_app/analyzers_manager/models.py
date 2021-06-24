from enum import Enum

from django.db import models
from django.contrib.postgres import fields as postgres_fields


class Statuses(Enum):
    FAILED = 0
    PENDING = 1
    RUNNING = 2
    SUCCESS = 3


class AnalyzerReport(models.Model):
    Statuses = Statuses

    analyzer_name = models.CharField(max_length=128)
    job = models.ForeignKey(
        "api_app.Job", related_name="analyzer_reports", on_delete=models.CASCADE
    )

    status = models.CharField(
        max_length=50,
        choices=[(s.name, s.name) for s in Statuses],
    )
    report = models.JSONField(default=dict)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512, blank=True, default=list)
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def __str__(self):
        return f"AnalyzerReport(job:#{self.job_id}, {self.analyzer_name})"
