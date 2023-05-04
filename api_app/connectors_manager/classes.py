# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
from typing import Optional, Type

import requests
from django.conf import settings

from api_app.core.classes import Plugin
from certego_saas.apps.user.models import User

from ..core.models import Parameter
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

    @classmethod
    @property
    def python_base_path(cls):
        return settings.BASE_CONNECTOR_PYTHON_PATH

    @property
    def connector_name(self) -> str:
        return self._config.name

    @classmethod
    @property
    def report_model(cls) -> Type[ConnectorReport]:
        return ConnectorReport

    @classmethod
    @property
    def config_model(cls) -> Type[ConnectorConfig]:
        return ConnectorConfig

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
        super().before_run()
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
        super().after_run()
        logger.info(f"FINISHED connector: {self.__repr__()}")

    @classmethod
    def health_check(cls, connector_name: str, user: User) -> Optional[bool]:
        """
        basic health check: if instance is up or not (timeout - 10s)
        """
        ccs = cls.config_model.objects.filter(name=connector_name, disabled=False)
        if not ccs.count():
            raise ConnectorRunException(f"Unable to find connector {connector_name}")
        for cc in ccs:
            cc: ConnectorConfig
            if cc.is_runnable(user):
                param: Parameter = cc.parameters.filter(name__startswith="url").first()
                if param:
                    try:
                        plugin_config = param.get_first_value(user)
                    except RuntimeError:
                        return False
                    else:
                        url = plugin_config.value
                        if url.startswith("http"):
                            if settings.STAGE_CI:
                                return True
                            try:
                                requests.head(url, timeout=10)
                            except requests.exceptions.ConnectionError:
                                health_status = False
                            except requests.exceptions.Timeout:
                                health_status = False
                            else:
                                health_status = True

                            return health_status
        raise ConnectorRunException(
            f"Unable to find configured connector {connector_name}"
        )
