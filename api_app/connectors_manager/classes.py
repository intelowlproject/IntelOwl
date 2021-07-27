# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.utils import timezone
import logging

from ..exceptions import (
    ConnectorConfigurationException,
    ConnectorRunException,
)

from api_app.core.classes import Plugin
from .models import ConnectorReport


logger = logging.getLogger(__name__)


class Connector(Plugin):
    """
    Abstract class for all Connectors.
    Inherit from this branch when defining a connector.
    Need to overrwrite `set_params(self, params: dict)`
     and `run(self)` functions.
    """

    @property
    def connector_name(self) -> str:
        return self._config.name

    def init_report_object(self) -> ConnectorReport:
        """
        Returns report object set in *start* fn
        """
        # unique constraint ensures only one report is possible
        _report_qs = ConnectorReport.objects.filter(
            job_id=self.job_id, connector_name=self.connector_name
        )
        if _report_qs.exists():  # case: recurring connector run
            _report_qs.update(
                report={},
                errors=[],
                status=ConnectorReport.Statuses.PENDING.name,
                task_id=self.kwargs["task_id"],
                start_time=timezone.now(),
                end_time=timezone.now(),
            )
            return _report_qs[0]
        else:
            return ConnectorReport.objects.create(
                job_id=self.job_id,
                connector_name=self.connector_name,
                report={},
                errors=[],
                status=ConnectorReport.Statuses.PENDING.name,
                task_id=self.kwargs["task_id"],
            )

    def get_exceptions_to_catch(self) -> list:
        return (
            ConnectorConfigurationException,
            ConnectorRunException,
        )

    def get_error_message(self, err, is_base_err=False):
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Connector error'}: '{err}'"
        )

    def before_run(self):
        logger.info(f"STARTED connector: {self.__repr__()}")

    def after_run(self):
        logger.info(f"FINISHED connector: {self.__repr__()}")

    def __repr__(self):
        return f"({self.connector_name}, job: #{self.job_id})"
