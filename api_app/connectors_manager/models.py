# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from django.conf import settings
from django.db import models

from api_app.connectors_manager.exceptions import ConnectorConfigurationException
from api_app.core.models import AbstractConfig, AbstractReport
from api_app.models import TLP, PluginConfig


class ConnectorReport(AbstractReport):
    ...

class ConnectorConfig(AbstractConfig):
    maximum_tlp = models.CharField(
        null=False, default=TLP.WHITE, choices=TLP.choices, max_length=50
    )
    run_on_failure = models.BooleanField(null=False, default=True)

    @classmethod
    def _get_type(cls) -> str:
        return PluginConfig.PluginType.CONNECTOR

    @classmethod
    @property
    def report_model(cls) -> Type[ConnectorReport]:
        return ConnectorReport

    @property
    def python_path(self) -> str:
        return settings.BASE_CONNECTOR_PYTHON_PATH

    @classmethod
    @property
    def config_exception(cls):
        return ConnectorConfigurationException
