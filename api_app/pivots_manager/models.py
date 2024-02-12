import logging
import typing
from typing import Type

from django.contrib.contenttypes.fields import GenericRelation

from api_app.pivots_manager.queryset import PivotConfigQuerySet, PivotReportQuerySet
from api_app.queryset import PythonConfigQuerySet

if typing.TYPE_CHECKING:
    from api_app.serializers.plugin import PythonConfigSerializer

from django.db import models
from django.utils.functional import cached_property

from api_app.choices import PythonModuleBasePaths
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import AbstractReport, Job, PythonConfig, PythonModule
from api_app.pivots_manager.exceptions import PivotConfigurationException

logger = logging.getLogger(__name__)


class PivotReport(AbstractReport):
    objects = PivotReportQuerySet.as_manager()
    config = models.ForeignKey(
        "PivotConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("config", "job")]
        indexes = AbstractReport.Meta.indexes


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
    ending_job = models.OneToOneField(
        Job,
        on_delete=models.CASCADE,
        related_name="pivot_parent",
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
    objects = PivotConfigQuerySet.as_manager()
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={"base_path": PythonModuleBasePaths.Pivot.value},
    )

    related_analyzer_configs = models.ManyToManyField(
        "analyzers_manager.AnalyzerConfig", related_name="pivots", blank=True
    )
    related_connector_configs = models.ManyToManyField(
        "connectors_manager.ConnectorConfig", related_name="pivots", blank=True
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        on_delete=models.PROTECT,
        related_name="executed_by_pivot",
        null=False,
        blank=False,
    )
    orgs_configuration = GenericRelation(
        "api_app.OrganizationPluginConfiguration", related_name="%(class)s"
    )

    def _generate_full_description(self) -> str:
        plugins_name = ", ".join(
            self.related_configs.all().values_list("name", flat=True)
        )
        return (
            f"Pivot for plugins {plugins_name}"
            " that executes"
            f" playbook {self.playbook_to_execute.name}"
        )

    @property
    def related_configs(self) -> PythonConfigQuerySet:
        return (
            self.related_analyzer_configs.all() or self.related_connector_configs.all()
        )

    @classmethod
    @property
    def plugin_type(cls) -> str:
        return "5"

    @classmethod
    @property
    def serializer_class(cls) -> Type["PythonConfigSerializer"]:
        from api_app.pivots_manager.serializers import PivotConfigSerializer

        return PivotConfigSerializer

    @classmethod
    @property
    def config_exception(cls):
        return PivotConfigurationException

    def clean(self):
        super().clean()
