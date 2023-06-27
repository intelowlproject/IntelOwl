import io
import logging
from typing import Any, Generator, List

from django.core.files import File
from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils.functional import cached_property

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.models import Job
from api_app.pivots_manager.validators import pivot_regex_validator
from api_app.visualizers_manager.models import VisualizerConfig

logger = logging.getLogger(__name__)


class Pivot(models.Model):
    starting_job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
        related_name="pivot_children",
        null=False,
        editable=False,
    )
    pivot_config = models.ForeignKey(
        "PivotConfig",
        on_delete=models.PROTECT,
        null=False,
        related_name="pivots",
        editable=False,
    )
    ending_job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
        related_name="pivot_parents",
        null=False,
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


class PivotConfig(AbstractConfig):
    name = models.CharField(
        max_length=100,
        null=False,
        validators=[pivot_regex_validator],
    )
    analyzer_config = models.ForeignKey(
        AnalyzerConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )
    connector_config = models.ForeignKey(
        ConnectorConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )
    visualizer_config = models.ForeignKey(
        VisualizerConfig,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=True,
        blank=True,
    )

    field = models.CharField(
        max_length=256,
        null=False,
        blank=False,
        help_text="Dotted path to the field",
        validators=[pivot_regex_validator],
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        on_delete=models.PROTECT,
        related_name="executed_by_pivot",
        null=False,
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
            models.Index(fields=["analyzer_config"]),
            models.Index(fields=["connector_config"]),
            models.Index(fields=["visualizer_config"]),
            models.Index(fields=["playbook_to_execute"]),
        ]

    def clean_config(self) -> None:
        from django.core.exceptions import ValidationError

        if (
            sum(
                (
                    bool(self.analyzer_config),
                    bool(self.connector_config),
                    bool(self.visualizer_config),
                )
            )
            != 1
        ):
            raise ValidationError(
                "You must have exactly one between"
                " `analyzer`, `connector` and `visualizer"
            )

    def clean(self) -> None:
        super().clean()
        self.clean_config()

    @cached_property
    def config(self) -> AbstractConfig:
        return self.analyzer_config or self.connector_config or self.visualizer_config

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
        if isinstance(value, list):
            logger.info(f"Config {self.name} retrieved value {value}")
            yield from value
        else:
            logger.info(f"Config {self.name} retrieved value {value}")
            yield value

    def _get_serializer(self, report: AbstractReport):
        from api_app.analyzers_manager.constants import AllTypes

        values = self.get_value(report)
        if AllTypes.FILE.value in self.playbook_to_execute.type:
            return self._get_file_serializer(values, report.job.tlp, report.job.user)
        else:
            return self._get_observable_serializer(values, report.job.tlp, report.job.user)

    def _get_observable_serializer(self, values:Generator[Any, None, None], tlp:str, user ):
        from api_app.serializers import ObservableAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        return ObservableAnalysisSerializer(
                data={
                    "playbooks_requested": [self.playbook_to_execute_id],
                    "observables": [(None, value) for value in values],
                    "send_task": True,
                    "tlp": tlp,
                },
                context={"request": MockUpRequest(user=user)},
                many=True,
            )

    def _get_file_serializer(self, values: Generator[bytes, None, None], tlp:str, user):
        from api_app.serializers import FileAnalysisSerializer
        from tests.mock_utils import MockUpRequest

        files = [File(io.BytesIO(data), name=f"{self.field}.{i}") for i, data in enumerate(values)]
        return FileAnalysisSerializer(
            data={
                "playbooks_requested": [self.playbook_to_execute_id],
                "files": files,
                "file_names:":[file.name for file in files],
                "send_task": True,
                "tlp": tlp,
            },
            context={"request": MockUpRequest(user=user)},
            many=True,
        )

    def _create_jobs(
        self, report: AbstractReport, send_task: bool = True
    ) -> Generator[Job, None, None]:

        try:
            serializer = self._get_serializer(report)
        except ValueError as e:
            logger.exception(e)
            raise
        else:
            serializer.is_valid(raise_exception=True)
            yield from serializer.save(send_task=send_task)

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

        ending_jobs = self._create_jobs(report)

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


@receiver(pre_save, sender=PivotConfig)
def pre_save_pivot_config(sender, instance, raw, using, update_fields, *args, **kwargs):
    config = instance.config
    instance.description = (
        f"Pivot object for plugin {config.name}"
        f" using field {instance.field}"
        " that creates job using"
        f" playbook {instance.playbook_to_execute.name}"
    )
    instance.name = (
        f"{config.name}.{instance.field}.{instance.playbook_to_execute.name}"
    )
    return instance
