import abc
import logging
from typing import Any, Generator, Type

from api_app.choices import PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.models import AbstractReport
from api_app.pivots_manager.exceptions import (
    PivotConfigurationException,
    PivotRunException,
)
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.queryset import PythonConfigQuerySet

logger = logging.getLogger(__name__)


class Pivot(Plugin, metaclass=abc.ABCMeta):
    @classmethod
    @property
    def python_base_path(cls):
        return PythonModuleBasePaths.Pivot.value

    @property
    def related_configs(self) -> PythonConfigQuerySet:
        return self._config.related_configs

    @property
    def related_reports(self) -> Generator[AbstractReport, None, None]:
        for related_config in self.related_configs:
            yield related_config.reports.get(job=self._job)

    @classmethod
    @property
    def report_model(cls) -> Type[PivotReport]:
        return PivotReport

    @classmethod
    @property
    def config_model(cls) -> Type[PivotConfig]:
        return PivotConfig

    def should_run(self) -> bool:
        # by default, the pivot run IF every report attached to it was success
        return all(
            x.status == self.report_model.Status.SUCCESS.value
            for x in self.related_reports
        )

    def get_value_to_pivot_to(self) -> Any:
        raise NotImplementedError()

    def run(self) -> Any:
        to_run = self.should_run()
        report = {"create_job": to_run, "jobs_id": []}
        if to_run:
            content = self.get_value_to_pivot_to()
            logger.info(f"Creating jobs from {content}")
            for job in self._config.create_jobs(content, self._job.tlp, self._user):
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
