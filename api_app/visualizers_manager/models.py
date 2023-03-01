# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from django.conf import settings
from django.db import models

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.models import AbstractConfig, AbstractReport


class VisualizerReport(AbstractReport):
    job = models.ForeignKey(
        "api_app.Job", related_name="visualizer_reports", on_delete=models.CASCADE
    )

    class Meta:
        unique_together = [("name", "job")]

    @property
    def visualizer_name(self) -> str:
        return self.name


class VisualizerConfig(AbstractConfig):
    analyzers = models.ManyToManyField(
        AnalyzerConfig, related_name="visualizers", blank=True
    )
    connectors = models.ManyToManyField(
        ConnectorConfig, related_name="visualizers", blank=True
    )

    @classmethod
    def _get_type(cls) -> str:
        from api_app.models import PluginConfig

        return PluginConfig.PluginType.VISUALIZER

    @property
    def python_path(self) -> str:
        return settings.BASE_VISUALIZER_PYTHON_PATH

    @classmethod
    @property
    def report_model(cls) -> Type[VisualizerReport]:
        return VisualizerReport
