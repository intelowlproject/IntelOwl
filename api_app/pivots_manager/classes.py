import abc
import logging
from typing import Any, Optional, Tuple, Type

from django.db.models import QuerySet

from api_app.choices import PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.decorators import classproperty
from api_app.models import AbstractReport
from api_app.pivots_manager.exceptions import (
    PivotConfigurationException,
    PivotRunException,
)
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.queryset import PythonConfigQuerySet

logger = logging.getLogger(__name__)


class Pivot(Plugin, metaclass=abc.ABCMeta):
    @classproperty
    def python_base_path(cls):
        return PythonModuleBasePaths.Pivot.value

    @property
    def related_configs(self) -> PythonConfigQuerySet:
        self._config: PivotConfig
        return self._config.related_configs

    @property
    def related_reports(self) -> QuerySet:
        report_class: Type[AbstractReport] = self.related_configs.model.report_class
        return report_class.objects.filter(
            config__in=self.related_configs, job=self._job
        )

    @classproperty
    def report_model(cls) -> Type[PivotReport]:
        return PivotReport

    @classproperty
    def config_model(cls) -> Type[PivotConfig]:
        return PivotConfig

    def should_run(self) -> Tuple[bool, Optional[str]]:
        # by default, the pivot run IF every report attached to it was success
        result = not self.related_reports.exclude(
            status=self.report_model.STATUSES.SUCCESS.value
        ).exists()
        return (
            result,
            f"All necessary reports{'' if result else ' do not'} have success status",
        )

    def get_value_to_pivot_to(self) -> Any:
        raise NotImplementedError()

    def before_run(self):
        super().before_run()
        self._config: PivotConfig
        self._config.validate_playbooks(self._user)

    def get_playbook_to_execute(self):
        self._config: PivotConfig
        return self._config.playbooks_choice.first()

    def run(self) -> Any:
        self._config: PivotConfig
        to_run, motivation = self.should_run()
        report = {"create_job": to_run, "motivation": motivation, "jobs_id": []}
        if to_run:
            content = self.get_value_to_pivot_to()
            logger.info(f"Creating jobs from {content}")
            for job in self._config.create_jobs(
                content,
                self._job.tlp,
                self._user,
                parent_job=self._job,
                playbook_to_execute=self.get_playbook_to_execute(),
            ):
                report["jobs_id"].append(job.pk)
                PivotMap.objects.create(
                    starting_job=self._job, ending_job=job, pivot_config=self._config
                )
        else:
            logger.info(f"Skipping job creation for {self._config.name}")
        return report

    def get_exceptions_to_catch(self) -> list:
        return [
            PivotConfigurationException,
            PivotRunException,
        ]
