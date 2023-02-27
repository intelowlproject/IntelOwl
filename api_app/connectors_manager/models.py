# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from django.conf import settings
from django.db import models

from api_app.core.models import AbstractConfig, AbstractReport
from api_app.models import TLP, PluginConfig


class ConnectorReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="connector_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]

    @property
    def connector_name(self) -> str:
        return self.name


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
