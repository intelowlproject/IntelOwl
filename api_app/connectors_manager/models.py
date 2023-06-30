# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.db import models

from api_app.choices import TLP
from api_app.connectors_manager.exceptions import ConnectorConfigurationException
from api_app.models import AbstractReport, PythonConfig


class ConnectorReport(AbstractReport):
    config = models.ForeignKey(
        "ConnectorConfig", related_name="reports", null=False, on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("config", "job")]


class ConnectorConfig(PythonConfig):
    maximum_tlp = models.CharField(
        null=False, default=TLP.CLEAR, choices=TLP.choices, max_length=50
    )
    run_on_failure = models.BooleanField(null=False, default=True)

    @classmethod
    @property
    def plugin_type(cls) -> str:
        return "2"

    @property
    def python_base_path(self) -> str:
        return settings.BASE_CONNECTOR_PYTHON_PATH

    @classmethod
    @property
    def config_exception(cls):
        return ConnectorConfigurationException
