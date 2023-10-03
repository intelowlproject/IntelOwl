import logging
import typing
from typing import Type

from django.core.exceptions import ValidationError
from django.db.models import Q

from api_app.validators import plugin_name_validator

if typing.TYPE_CHECKING:
    from api_app.serializers import PythonConfigSerializer

from django.db import models
from django.utils.functional import cached_property

from api_app.choices import PythonModuleBasePaths
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import AbstractReport, Job, PythonConfig, PythonModule
from api_app.pivots_manager.exceptions import PivotConfigurationException

logger = logging.getLogger(__name__)


class PivotReport(AbstractReport):
    config = models.ForeignKey(
        "PivotConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("config", "job")]


class PivotMap(models.Model):
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
        default=None,
        null=True,
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

    def __str__(self):
        return f"Job {self.starting_job_id} -> Job {self.ending_job_id}"

    @cached_property
    def report(self) -> typing.Optional[AbstractReport]:
        if self.pivot_config:
            return self.pivot_config.reports.get(job=self.starting_job)
        return None

    @cached_property
    def owner(self) -> str:
        return self.starting_job.user.username


class PivotConfig(PythonConfig, CreateJobsFromPlaybookInterface):
    name = models.CharField(
        max_length=100, null=False, validators=[plugin_name_validator], unique=True
    )
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={"base_path": PythonModuleBasePaths.Pivot.value},
    )

    related_analyzer_config = models.ForeignKey(
        "analyzers_manager.AnalyzerConfig",
        related_name="pivots",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    related_connector_config = models.ForeignKey(
        "connectors_manager.ConnectorConfig",
        related_name="pivots",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        on_delete=models.PROTECT,
        related_name="executed_by_pivot",
        null=False,
        blank=False,
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=Q(related_analyzer_config__isnull=True)
                | Q(related_connector_config__isnull=True),
                name="pivot_config_all_null_configs",
            ),
            models.CheckConstraint(
                check=Q(related_analyzer_config__isnull=False)
                | Q(related_connector_config__isnull=False),
                name="pivot_config_no_null_configs",
            ),
        ]

    @property
    def related_config(self):
        return self.related_analyzer_config or self.related_connector_config

    @classmethod
    def plugin_type(cls) -> str:
        return "5"

    @classmethod
    def serializer_class(cls) -> Type["PythonConfigSerializer"]:
        from api_app.pivots_manager.serializers import PivotConfigSerializer

        return PivotConfigSerializer

    @classmethod
    def config_exception(cls):
        return PivotConfigurationException

    def clean_config(self):
        if self.related_analyzer_config and self.related_connector_config:
            raise ValidationError("You can't set both analyzer and connector")

    def clean_playbook_to_execute(self):
        if self.id and self.playbook_to_execute in self.used_by_playbooks.all():
            raise ValidationError("Recursive playbook usage in pivot")

    def clean(self):
        super().clean()
        self.clean_playbook_to_execute()
