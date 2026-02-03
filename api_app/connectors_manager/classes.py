# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from typing import Type

from api_app.decorators import classproperty

from ..choices import PythonModuleBasePaths, ReportStatus
from ..classes import Plugin
from .exceptions import ConnectorConfigurationException, ConnectorRunException
from .models import ConnectorConfig, ConnectorReport

logger = logging.getLogger(__name__)


class Connector(Plugin, metaclass=abc.ABCMeta):
    """
    Abstract class for all Connectors.
    Inherit from this branch when defining a connector.
    Need to overrwrite `set_params(self, params: dict)`
     and `run(self)` functions.
    """

    @classproperty
    def python_base_path(cls):
        return PythonModuleBasePaths.Connector.value

    @classproperty
    def report_model(cls) -> Type[ConnectorReport]:
        return ConnectorReport

    @classproperty
    def config_model(cls) -> Type[ConnectorConfig]:
        return ConnectorConfig

    def get_exceptions_to_catch(self) -> list:
        return [
            ConnectorConfigurationException,
            ConnectorRunException,
        ]

    def before_run(self):
        super().before_run()
        logger.info(f"STARTED connector: {self.__repr__()}")
        self._config: ConnectorConfig
        # an analyzer can start
        # if the run_on_failure flag is set
        # if there are no analyzer_reports
        # it all the analyzer_reports are not failed
        if (
            self._config.run_on_failure
            or not self._job.analyzerreports.count()
            or self._job.analyzerreports.exclude(status=ReportStatus.FAILED.value).exists()
        ):
            logger.info(
                f"Running connector {self.__class__.__name__} "
                f"even if job status is {self._job.status} because"
                "run on failure is set"
            )
        else:
            raise ConnectorRunException(
                f"An analyzer has failed, unable to run connector {self.__class__.__name__}"
            )

    def after_run(self):
        super().after_run()
        logger.info(f"FINISHED connector: {self.__repr__()}")
