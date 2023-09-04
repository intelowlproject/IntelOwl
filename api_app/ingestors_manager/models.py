# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Any, Generator

from django.conf import settings
from django.db import models
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from api_app.ingestors_manager.exceptions import IngestorConfigurationException
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import AbstractReport, PythonConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.queryset import IngestorQuerySet

logger = logging.getLogger(__name__)


class IngestorReport(AbstractReport):
    config = models.ForeignKey(
        "IngestorConfig", related_name="reports", on_delete=models.CASCADE
    )
    report = models.JSONField(default=list, validators=[])
    name = models.CharField(blank=True, default="", max_length=50)
    task_id = models.UUIDField(null=True, blank=True)
    job = models.ForeignKey(
        "api_app.Job",
        related_name="%(class)ss",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    max_size_report = models.IntegerField(default=None, null=True, blank=True)

    class Meta:
        ordering = ["pk"]

    def clean_report(self):
        if isinstance(self.report, list) and self.max_size_report is not None:
            len_report = len(self.report)
            if len_report > self.max_size_report:
                logger.warning(
                    f"Report {self.pk} has {len_report} "
                    f"while max_size is {self.max_size_report}"
                )
                self.report = self.report[: self.max_size_report]

    def clean(self):
        super().clean()
        self.clean_report()


class IngestorConfig(PythonConfig, CreateJobsFromPlaybookInterface):
    objects = IngestorQuerySet.as_manager()

    playbook_to_execute = models.ForeignKey(
        PlaybookConfig,
        related_name="ingestors",
        on_delete=models.CASCADE,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ingestors",
    )
    schedule = models.ForeignKey(
        CrontabSchedule, related_name="ingestors", on_delete=models.PROTECT
    )
    periodic_task = models.OneToOneField(
        PeriodicTask, related_name="ingestor", on_delete=models.PROTECT
    )
    disabled_in_organizations = None

    def get_values(self, report: AbstractReport) -> Generator[Any, None, None]:
        yield from report.report

    @classmethod
    @property
    def plugin_type(cls) -> str:
        return "4"

    @classmethod
    @property
    def config_exception(cls):
        return IngestorConfigurationException

    @classmethod
    @property
    def serializer_class(cls):
        from api_app.ingestors_manager.serializers import IngestorConfigSerializer

        return IngestorConfigSerializer
