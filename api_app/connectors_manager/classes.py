# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, Optional
import requests

from ..exceptions import (
    ConnectorConfigurationException,
    ConnectorRunException,
)

from api_app.core.classes import Plugin
from .models import ConnectorReport
from .dataclasses import ConnectorConfig


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

    @property
    def report_model(self):
        return ConnectorReport

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

    @classmethod
    def health_check(
        cls, url_loc: Dict[str, str], cc: ConnectorConfig
    ) -> Optional[bool]:
        """
        basic health check: if instance is up or not (timeout - 10s)
        url_loc: whether url is in config/secrets or given directly
          "secrets/config/url": "value"
        """

        url = None
        health_status = None

        if url_loc.get("url", None) is not None:
            url = url_loc["url"]
        elif url_loc.get("secrets", None) is not None:
            secret_dict = cc._read_secrets(url_loc["secrets"])
            url = secret_dict[url_loc["secrets"]]
        elif url_loc.get("config", None) is not None:
            url = cc.config[url_loc["config"]]

        if url is not None:
            try:
                requests.head(url, timeout=10)
                health_status = True
            except requests.exceptions.ConnectionError:
                health_status = False
            except requests.exceptions.Timeout:
                health_status = False

        return health_status
