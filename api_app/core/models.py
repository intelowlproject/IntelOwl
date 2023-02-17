# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Dict

from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


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
    parent_playbook = models.CharField(max_length=128, default="", blank=True)

    # meta
    class Meta:

        abstract = True

    def __str__(self):
        return f"{self.__class__.__name__}(job:#{self.job_id}, {self.name})"

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

    @classmethod
    def get_or_create_failed(
        cls, job_id: int, name: str, defaults: Dict, error: str
    ) -> "AbstractReport":
        logger.warning(
            f"(job: #{job_id}, {cls.__name__}:{name}) -> set as {cls.Status.FAILED}. "
            f"Error: {error}"
        )
        report, _ = cls.objects.get_or_create(
            job_id=job_id, name=name, defaults=defaults
        )
        report.status = cls.Status.FAILED
        report.errors.append(error)
        report.save()
        return report
