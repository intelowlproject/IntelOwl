import logging
from typing import Any, Generator, List

from django.db import models
from django.utils.functional import cached_property

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers import ObservableAnalysisSerializer
from api_app.visualizers_manager.models import VisualizerConfig

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
            models.Index(fields=["config"]),
        ]

    @property
    def value(self) -> Any:
        return self.ending_job.analyzed_object_name


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

    def clean_config(self) -> None:
        from django.core.exceptions import ValidationError

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

    def get_value(self, report: AbstractReport) -> Generator[Any, None, None]:
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
        if isinstance(value, bytes):
            raise ValueError("At the moment we do not support pivoting to files")
        elif isinstance(value, list):
            logger.info(f"Config {self.name} retrieved value {value}")
            yield from value
        else:
            logger.info(f"Config {self.name} retrieved value {value}")
            yield value

    def _create_jobs(self, starting_job: Job) -> List[Job]:
        from tests.mock_utils import MockUpRequest

        try:
            report = self.config.reports.get(job=starting_job)
        except self.config.reports.model.DoesNotExist:
            logger.error(
                f"Job {starting_job.pk} does not have a report"
                f" for analyzer {self.config.name}"
            )
        else:
            try:
                # we do not want to calculate the classification here
                observables = [(None, value) for value in self.get_value(report)]
            except ValueError as e:
                logger.exception(e)
            else:
                serializer = ObservableAnalysisSerializer(
                    data={
                        "playbooks_requested": [self.playbook.pk],
                        "observables": observables,
                        "send_task": True,
                        "tlp": starting_job.tlp,
                    },
                    context={"request": MockUpRequest(user=starting_job.user)},
                    many=True,
                )
                serializer.is_valid(raise_exception=True)
                return serializer.save(send_task=True)
        return []

    def pivot_job(self, starting_job: Job) -> List[Pivot]:
        from rest_framework.exceptions import ValidationError

        try:
            ending_jobs = self._create_jobs(starting_job)
        except ValidationError as e:
            logger.exception(e)
            report = self.config.reports.get(job=starting_job)
            report.append_error("Unable to create pivots", save=True)
            return []
        else:
            pivots = []
            logger.info(f"Jobs create from pivot are {ending_jobs}")
            for ending_job in ending_jobs:
                pivot = Pivot(
                    starting_job=starting_job, config=self, ending_job=ending_job
                )
                pivot.full_clean()
                pivots.append(pivot)
                logger.info(f"Creating pivot {pivot.pk}")
            return Pivot.objects.bulk_create(pivots)
