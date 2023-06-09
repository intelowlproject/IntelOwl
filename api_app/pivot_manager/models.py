import logging
import uuid
from typing import Any, Generator

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.functional import cached_property

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import MultiplePlaybooksMultipleObservableAnalysisSerializer
from api_app.visualizers_manager.models import VisualizerConfig
from intel_owl.celery import DEFAULT_QUEUE

logger = logging.getLogger(__name__)


class Pivot(models.Model):
    starting_job = models.ForeignKey(
        Job, on_delete=models.CASCADE, related_name="pivot_children", null=False
    )
    config = models.ForeignKey("PivotConfig", on_delete=models.PROTECT, null=False)
    ending_job = models.ForeignKey(
        Job, on_delete=models.CASCADE, related_name="pivot_parents", null=False
    )

    class Meta:
        unique_together = ["starting_job", "config", "ending_job"]
        indexes = [
            models.Index(fields=["starting_job"]),
            models.Index(fields=["ending_job"]),
        ]


class PivotConfig(AbstractConfig):
    analyzer = models.ForeignKey(
        AnalyzerConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )
    connector = models.ForeignKey(
        ConnectorConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )
    visualizer = models.ForeignKey(
        VisualizerConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )

    field = models.CharField(
        max_length=256, null=False, blank=False, help_text="Dotted path to the field"
    )
    playbook = models.ForeignKey(
        PlaybookConfig, on_delete=models.PROTECT, related_name="pivots", null=False
    )

    class Meta:
        unique_together = [
            "analyzer",
            "connector",
            "visualizer",
            "field",
            "playbook",
        ]
        indexes = [
            models.Index(fields=["analyzer", "field", "playbook"]),
            models.Index(fields=["connector", "field", "playbook"]),
            models.Index(fields=["visualizer", "field", "playbook"]),
            models.Index(fields=["analyzer"]),
            models.Index(fields=["connector"]),
            models.Index(fields=["visualizer"]),
            models.Index(fields=["playbook"]),
        ]

    def clean_config(self):
        if sum((bool(self.analyzer), bool(self.connector), bool(self.visualizer))) != 1:
            raise ValidationError(
                "You must have exactly one between"
                " `analyzer`, `connector` and `visualizer"
            )

    def clean(self) -> None:
        super().clean()
        self.clean_config()

    @cached_property
    def config(self) -> AbstractConfig:
        return self.analyzer or self.connector or self.visualizer

    def _get_value(self, report: AbstractReport) -> Generator[Any, None, None]:
        value = report.report

        for key in self.field.split("."):
            value = value[key]

        if isinstance(value, (int, dict)):
            raise ValueError(f"You can't use a {type(value)} as pivot")
        if isinstance(value, bytes):
            raise ValueError("At the moment we do not support pivoting to files")
        elif isinstance(value, list):
            yield from value
        else:
            yield value

    def get_value(self, job: Job) -> Generator[Any, None, None]:
        try:
            report = self.config.reports.get(job=job)
        except self.config.reports.model.DoesNotExist:
            logger.error(
                f"Job {job.pk} does not have a report for analyzer {self.config.name}"
            )
            raise
        return self._get_value(report)

    def pivot_job(self, starting_job: Job) -> Generator[Pivot, None, None]:
        from intel_owl.tasks import job_pipeline
        from tests.mock_utils import MockUpRequest

        values = self.get_value(starting_job)
        serializer = MultiplePlaybooksMultipleObservableAnalysisSerializer(
            data={
                "playbooks_requested": [self.playbook.pk],
                "observables": list(values),
            },
            context={"request": MockUpRequest(user=starting_job.user)},
        )
        ending_jobs = serializer.save()
        for ending_job in ending_jobs:
            job_pipeline.apply_async(args=[ending_job.pk], routing_key=DEFAULT_QUEUE, MessageGroupId=str(uuid.uuid4()))
            yield Pivot.objects.create(
                starting_job=starting_job, config=self, ending_job=ending_job
            )
