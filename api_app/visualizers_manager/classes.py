# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from typing import Type

from django.db.models import QuerySet

from api_app.core.classes import Plugin
from api_app.visualizers_manager.exceptions import (
    VisualizerConfigurationException,
    VisualizerRunException,
)
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport

logger = logging.getLogger(__name__)


class Visualizer(Plugin, metaclass=abc.ABCMeta):
    @property
    def visualizer_name(self) -> str:
        return self._config.name

    @classmethod
    @property
    def report_model(cls):
        return VisualizerReport

    @classmethod
    @property
    def config_model(cls) -> Type[VisualizerConfig]:
        return VisualizerConfig

    def get_exceptions_to_catch(self) -> list:
        return [
            VisualizerConfigurationException,
            VisualizerRunException,
        ]

    def get_error_message(self, err, is_base_err=False):
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Connector error'}: '{err}'"
        )

    def before_run(self, *args, **kwargs):
        logger.info(f"STARTED visualizer: {self.__repr__()}")

    def after_run(self):
        logger.info(f"FINISHED visualizer: {self.__repr__()}")

    def analyzer_reports(self) -> QuerySet:
        self._config: VisualizerConfig
        return self._config.analyzers.filter(reports__job=self._job)

    def connectors_reports(self) -> QuerySet:
        self._config: VisualizerConfig
        return self._config.connectors.filter(reports__job=self._job)
