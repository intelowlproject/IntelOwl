# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import QuerySet
from django_celery_beat.models import CrontabSchedule, PeriodicTask

from api_app.choices import PythonModuleBasePaths
from api_app.decorators import classproperty
from api_app.ingestors_manager.exceptions import IngestorConfigurationException
from api_app.ingestors_manager.queryset import IngestorQuerySet, IngestorReportQuerySet
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import (
    AbstractReport,
    Job,
    OrganizationPluginConfiguration,
    PythonConfig,
    PythonModule,
)
from api_app.playbooks_manager.models import PlaybookConfig

logger = logging.getLogger(__name__)


class IngestorReport(AbstractReport):
    """
    Model representing an Ingestor Report.

    Attributes:
        config (ForeignKey): Reference to the IngestorConfig.
        report (JSONField): JSON field storing the report data.
        name (CharField): Name of the report.
        task_id (UUIDField): Task ID associated with the report.
        job (ForeignKey): Reference to the related Job.
        max_size_report (IntegerField): Maximum size of the report.
    """

    objects = IngestorReportQuerySet.as_manager()
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
        indexes = AbstractReport.Meta.indexes

    def clean_report(self):
        """
        Cleans the report by trimming it to the maximum size if necessary.
        """
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
    """
    Model representing an Ingestor Configuration.

    Attributes:
        python_module (ForeignKey): Reference to the PythonModule.
        playbooks_choice (ManyToManyField): Many-to-many relationship with PlaybookConfig.
        user (ForeignKey): Reference to the user.
        schedule (ForeignKey): Reference to the CrontabSchedule.
        periodic_task (OneToOneField): One-to-one relationship with PeriodicTask.
        maximum_jobs (IntegerField): Maximum number of jobs.
        delay (DurationField): Delay between jobs.
        org_configuration (None): Placeholder for organization configuration.
    """

    objects = IngestorQuerySet.as_manager()
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={"base_path": PythonModuleBasePaths.Ingestor.value},
    )
    playbooks_choice = models.ManyToManyField(
        PlaybookConfig,
        related_name="ingestors",
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
    maximum_jobs = models.IntegerField(default=10)
    delay = models.DurationField(
        default=timedelta, help_text="Expects data in the format 'DD HH:MM:SS'"
    )

    org_configuration = None

    @property
    def disabled_in_organizations(self) -> QuerySet:
        return OrganizationPluginConfiguration.objects.none()

    @classproperty
    def plugin_type(cls) -> str:
        return "4"

    @classproperty
    def config_exception(cls):
        return IngestorConfigurationException

    @classproperty
    def serializer_class(cls):
        from api_app.ingestors_manager.serializers import IngestorConfigSerializer

        return IngestorConfigSerializer

    def generate_empty_report(self, job: Job, task_id: str, status: str):
        # every time we execute the ingestor we have to create a new report
        # instead of using the update/create
        # because we do not have the same unique constraints
        return self.python_module.python_class.report_model.objects.create(
            job=job,
            config=self,
            status=status,
            task_id=task_id,
            max_size_report=self.maximum_jobs,
            parameters=self._get_params(self.user, {}),
        )

    def get_or_create_org_configuration(self):
        return None
