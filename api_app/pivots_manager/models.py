import logging
from typing import Any, Generator, List

from django.db import models
from django.utils.functional import cached_property

from api_app.interfaces import (
    AttachedToPythonConfigInterface,
    CreateJobsFromPlaybookInterface,
)
from api_app.models import AbstractConfig, AbstractReport, Job
from api_app.pivots_manager.validators import pivot_regex_validator

logger = logging.getLogger(__name__)


class Pivot(models.Model):
    starting_job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
        related_name="pivot_children",
        editable=False,
    )
    pivot_config = models.ForeignKey(
        "PivotConfig",
        on_delete=models.PROTECT,
        related_name="pivots",
        editable=False,
    )
    ending_job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
        related_name="pivot_parents",
        editable=False,
    )

    class Meta:
        unique_together = [
            ("starting_job", "pivot_config", "ending_job"),
        ]
        indexes = [
            models.Index(fields=["starting_job"]),
            models.Index(fields=["pivot_config"]),
            models.Index(fields=["ending_job"]),
        ]

    @cached_property
    def value(self) -> Any:
        return self.ending_job.analyzed_object_name

    @cached_property
    def report(self) -> AbstractReport:
        return self.pivot_config.config.reports.get(job=self.starting_job)

    @cached_property
    def owner(self) -> str:
        return self.starting_job.user.username


class PivotConfig(
    AbstractConfig, CreateJobsFromPlaybookInterface, AttachedToPythonConfigInterface
):
    name = models.CharField(
        max_length=100,
        validators=[pivot_regex_validator],
    )

    field = models.CharField(
        max_length=256,
        help_text="Dotted path to the field",
        validators=[pivot_regex_validator],
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        on_delete=models.PROTECT,
        related_name="executed_by_pivot",
    )

    class Meta:
        unique_together = [
            (
                "analyzer_config",
                "field",
                "playbook_to_execute",
            ),
            (
                "connector_config",
                "field",
                "playbook_to_execute",
            ),
            (
                "visualizer_config",
                "field",
                "playbook_to_execute",
            ),
        ]
        indexes = [
            models.Index(fields=["playbook_to_execute"]),
        ] + AttachedToPythonConfigInterface.Meta.indexes

    def clean(self) -> None:
        super().clean()
        self.clean_config()

    def get_values(self, report: AbstractReport) -> Generator[Any, None, None]:
        value = report.report

        for key in self.field.split("."):
            try:
                value = value[key]
            except TypeError:
                if isinstance(value, list):
                    value = value[int(key)]
                else:
                    raise

        if isinstance(value, (int, dict)):
            raise ValueError(f"You can't use a {type(value)} as pivot")
        if isinstance(value, list):
            logger.info(f"Config {self.name} retrieved value {value}")
            yield from value
        else:
            logger.info(f"Config {self.name} retrieved value {value}")
            yield value

    def pivot_job(self, starting_job: Job) -> List[Pivot]:
        from rest_framework.exceptions import ValidationError

        # coherence check, should not happen
        if not self.config.__class__.objects.filter(
            playbooks=starting_job.playbook_to_execute
        ).exists():
            logger.error(
                f"Job {starting_job.pk}"
                f" playbook {starting_job.playbook_to_execute.pk}"
                f" is not connected to pivot {self.pk}"
            )

        try:
            report = self.config.reports.get(job=starting_job)
        except self.config.reports.model.DoesNotExist:
            logger.error(
                f"Job {starting_job.pk} does not have a report"
                f" for analyzer {self.config.name}"
            )
            return []

        ending_jobs = self._create_jobs(
            report, report.job.tlp, report.job.user, send_task=True
        )

        pivots = []
        logger.info(f"Jobs created from pivot are {ending_jobs}")
        try:
            for ending_job in ending_jobs:
                pivot = Pivot(
                    starting_job=starting_job, config=self, ending_job=ending_job
                )
                pivot.full_clean()
                pivots.append(pivot)
                logger.info(f"Creating pivot {pivot.pk}")
        except (ValidationError, ValueError, TypeError) as e:
            logger.exception(e)
            report.append_error("Unable to create pivots", save=True)
            return []
        else:
            return Pivot.objects.bulk_create(pivots)
