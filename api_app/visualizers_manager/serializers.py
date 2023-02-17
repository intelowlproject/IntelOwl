# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from pathlib import PosixPath
from typing import List

from django.conf import settings
from rest_framework import serializers as rfs
from rest_framework.exceptions import ValidationError

from api_app.core.serializers import AbstractConfigSerializer, BaseField
from api_app.models import PluginConfig, Position

from .models import VisualizerReport


class VisualizerConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `connector_config.json`.
    """

    connectors = rfs.ListField(child=rfs.CharField())
    analyzers = rfs.ListField(child=rfs.CharField())
    config = rfs.DictField(default={})
    secrets = rfs.DictField(default={})

    @classmethod
    @property
    def config_file_name(cls) -> str:
        return "visualizer_config.json"

    def validate_connectors(self, connectors: List[str]) -> List[str]:
        from api_app.connectors_manager.dataclasses import ConnectorConfig

        for connector in connectors:
            if connector not in ConnectorConfig.all().keys():
                raise ValidationError(f"Connector {connector} does not exists")
        return connectors

    def validate_analyzers(self, analyzers: List[str]) -> List[str]:
        from api_app.analyzers_manager.dataclasses import AnalyzerConfig

        for analyzer in analyzers:
            if analyzer not in AnalyzerConfig.all().keys():
                raise ValidationError(f"Analyzer {analyzer} does not exists")
        return analyzers

    @classmethod
    def _get_type(cls):
        return PluginConfig.PluginType.VISUALIZER

    @property
    def python_path(self) -> PosixPath:
        return settings.BASE_VISUALIZER_PYTHON_PATH


class VisualizerReportSerializer(rfs.ModelSerializer):
    class ReportSerializer(rfs.Serializer):
        priority = rfs.IntegerField(min_value=1, max_value=10)
        position = rfs.ChoiceField(choices=Position.choices)
        value = BaseField(required=True)

    type = rfs.CharField(default="visualizer")
    report = rfs.DictField(child=ReportSerializer())

    class Meta:
        model = VisualizerReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "runtime_configuration",
            "type",
        )
