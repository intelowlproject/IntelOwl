import logging
import typing
from typing import Type

from django.core.exceptions import ValidationError

from api_app.validators import plugin_name_validator

if typing.TYPE_CHECKING:
    from api_app.serializers import PythonConfigSerializer

from django.db import models
from django.utils.functional import cached_property

from api_app.choices import PythonModuleBasePaths
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.models import AbstractReport, Job, PythonConfig, PythonModule
from api_app.pivots_manager.exceptions import PivotConfigurationException
from api_app.pivots_manager.validators import pivot_regex_validator

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
        return f"Job {self.starting_job.pk} -> Job {self.ending_job.pk}"

    @cached_property
    def report(self) -> AbstractReport:
        return self.pivot_config.config.reports.get(job=self.starting_job)

    @cached_property
    def owner(self) -> str:
        return self.starting_job.user.username


class PivotConfig(PythonConfig, CreateJobsFromPlaybookInterface):
    name = models.CharField(
        max_length=100,
        null=False,
        validators=[plugin_name_validator],
    )
    field_to_compare = models.CharField(
        max_length=256,
        help_text="Dotted path to the field",
        validators=[pivot_regex_validator],
    )
    execute_on_python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="pivots",
        null=False,
        blank=False,
        limit_choices_to={
            "base_path__in": [
                PythonModuleBasePaths.FileAnalyzer.value,
                PythonModuleBasePaths.ObservableAnalyzer.value,
                PythonModuleBasePaths.Connector.value,
            ]
        },
    )
    python_module = models.ForeignKey(
        PythonModule,
        on_delete=models.PROTECT,
        related_name="%(class)ss",
        limit_choices_to={"base_path": PythonModuleBasePaths.Pivot.value},
    )
    playbook_to_execute = models.ForeignKey(
        "playbooks_manager.PlaybookConfig",
        on_delete=models.PROTECT,
        related_name="executed_by_pivot",
        null=False,
        blank=False,
    )

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

    def clean_playbook_to_execute(self):
        if self.id:
            if self.playbook_to_execute in self.used_by_playbooks:
                raise ValidationError("Recursive playbook usage in pivot")

    def clean(self):
        super().clean()
        self.clean_playbook_to_execute()

    class Meta:
        unique_together = [
            (
                "python_module",
                "execute_on_python_module",
                "playbook_to_execute",
            ),
            ("name",),
        ]
