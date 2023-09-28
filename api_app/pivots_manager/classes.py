import abc
import logging
from typing import Any, Type

from api_app.choices import PythonModuleBasePaths
from api_app.classes import Plugin
from api_app.pivots_manager.exceptions import (
    PivotConfigurationException,
    PivotFieldNotFoundException,
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

    def get_value(self, field: str) -> Any:
        content = self.related_report.report

        for key in field.split("."):
            try:
                content = content[key]
            except TypeError:
                if isinstance(content, list):
                    content = content[int(key)]
                else:
                    raise PivotFieldNotFoundException(field)

        if isinstance(content, (int, dict)):
            raise ValueError(f"You can't use a {type(content)} as pivot")
        return content

    def before_run(self):
        super().before_run()
        self._config: PivotConfig
        try:
            return self.get_value(self._config.field_to_compare)
        except PivotFieldNotFoundException as e:
            raise PivotRunException(str(e))

    def run(self) -> Any:
        raise NotImplementedError()

    def get_exceptions_to_catch(self) -> list:
        return [
            PivotConfigurationException,
            PivotRunException,
        ]

    def after_run_success(self, content: Any):
        logger.info(f"Creating jobs from {content}")
        to_run = bool(content)
        report = {"create_job": to_run, "jobs_id": []}
        if to_run:
            for job in self._config._create_jobs(content, self._job.tlp, self._user):
                report["jobs_id"].append(job.pk)
                PivotMap.objects.create(
                    starting_job=self._job, ending_job=job, pivot_config=self._config
                )
        return super().after_run_success(report)
