# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.utils import timezone


class Status(models.TextChoices):
    FAILED = "FAILED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    KILLED = "KILLED"


class AbstractReport(models.Model):
    # constants
    Status = Status

    # fields
    name = models.CharField(max_length=128)
    status = models.CharField(max_length=50, choices=Status.choices)
    report = models.JSONField(default=dict)
    errors = pg_fields.ArrayField(
        models.CharField(max_length=512), default=list, blank=True
    )
    runtime_configuration = models.JSONField(default=dict, null=True, blank=True)
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(default=timezone.now)
    task_id = models.UUIDField()  # tracks celery task id

    # If a playbook ran the process
    parent_playbook = models.CharField(max_length=128, null=True)

    # meta
    class Meta:

        abstract = True

    # properties
    @property
    def user(self) -> models.Model:
        return self.job.user

    @property
    def process_time(self) -> float:
        secs = (self.end_time - self.start_time).total_seconds()
        return round(secs, 2)

    def update_status(self, status: str, save=True):
        self.status = status
        if save:
            self.save(update_fields=["status"])

    def append_error(self, err_msg: str, save=True):
        self.errors.append(err_msg)
        if save:
            self.save(update_fields=["errors"])
