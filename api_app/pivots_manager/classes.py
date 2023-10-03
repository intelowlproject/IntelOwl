import abc
import logging
from typing import Any, Type

from api_app.choices import PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.pivots_manager.exceptions import (
    PivotConfigurationException,
    PivotRunException,
)
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport

logger = logging.getLogger(__name__)


class Pivot(Plugin, metaclass=abc.ABCMeta):
    @classmethod
    @property
    def python_base_path(cls):
        return PythonModuleBasePaths.Pivot.value

    @property
    def related_report(self):
        return self._config.related_config.__class__.objects.get(
            executed_in_jobs=self._job,
            python_module=self._config.related_config.python_module,
        ).reports.get(job=self._job)

    @classmethod
    @property
    def report_model(cls) -> Type[PivotReport]:
        return PivotReport

    @classmethod
    @property
    def config_model(cls) -> Type[PivotConfig]:
        return PivotConfig

    def should_run(self) -> bool:
        raise NotImplementedError()

    def get_value_to_pivot_to(self) -> Any:
        raise NotImplementedError()

    def run(self) -> Any:
        if to_run := self.should_run():
            content = self.get_value_to_pivot_to()
            logger.info(f"Creating jobs from {content}")
            report = {"create_job": to_run, "jobs_id": []}
            for job in self._config._create_jobs(content, self._job.tlp, self._user):
                report["jobs_id"].append(job.pk)
                PivotMap.objects.create(
                    starting_job=self._job, ending_job=job, pivot_config=self._config
                )
        else:
            logger.info(f"Skipping job creation for {self._config.name}")

    def get_exceptions_to_catch(self) -> list:
        return [
            PivotConfigurationException,
            PivotRunException,
        ]
