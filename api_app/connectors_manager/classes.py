# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from typing import Optional, Type

import requests

from api_app.core.classes import Plugin

from .dataclasses import ConnectorConfig
from .exceptions import ConnectorConfigurationException, ConnectorRunException
from .models import ConnectorReport

logger = logging.getLogger(__name__)


class Connector(Plugin, metaclass=abc.ABCMeta):
    """
    Abstract class for all Connectors.
    Inherit from this branch when defining a connector.
    Need to overrwrite `set_params(self, params: dict)`
     and `run(self)` functions.
    """

    @classmethod
    def get_config_class(cls) -> Type[ConnectorConfig]:
        return ConnectorConfig

    @property
    def connector_name(self) -> str:
        return self._config.name

    @property
    def report_model(self):
        return ConnectorReport

    def get_exceptions_to_catch(self) -> list:
        return [
            ConnectorConfigurationException,
            ConnectorRunException,
        ]

    def get_error_message(self, err, is_base_err=False):
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Connector error'}: '{err}'"
        )

    def before_run(self, *args, **kwargs):
        logger.info(f"STARTED connector: {self.__repr__()}")
        self._config: ConnectorConfig
        if self._job.status not in [
            self._job.Status.REPORTED_WITH_FAILS,
            self._job.Status.REPORTED_WITHOUT_FAILS,
        ]:
            if (
                self._config.run_on_failure
                and self._job.status == self._job.Status.FAILED
            ):
                logger.info(
                    f"Running connector {self.__class__.__name__} "
                    f"even if job status is {self._job.status} because"
                    "run on failure is set"
                )
            else:
                raise ConnectorRunException(
                    f"Job status is {self._job.status}, "
                    f"unable to run connector {self.__class__.__name__}"
                )

    def after_run(self):
        logger.info(f"FINISHED connector: {self.__repr__()}")

    def __repr__(self):
        return f"({self.connector_name}, job: #{self.job_id})"

    @classmethod
    def health_check(cls, connector_name: str) -> Optional[bool]:
        """
        basic health check: if instance is up or not (timeout - 10s)
        """
        health_status, url = None, None
        # todo this is already done by the caller, to optimize this
        cc = ConnectorConfig.get(connector_name)
        if cc is not None:
            url = cc.read_secrets(secrets_filter="url_key_name").get(
                "url_key_name", None
            )
            if url and url.startswith("http"):
                try:
                    requests.head(url, timeout=10)
                except requests.exceptions.ConnectionError:
                    health_status = False
                except requests.exceptions.Timeout:
                    health_status = False
                else:
                    health_status = True

        return health_status
