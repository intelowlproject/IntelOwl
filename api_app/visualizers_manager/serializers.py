# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer, BaseField
from api_app.models import Position

from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = VisualizerConfig
        fields = rfs.ALL_FIELDS


class VisualizerReportSerializer(rfs.ModelSerializer):
    class ReportSerializer(rfs.Serializer):
        priority = rfs.IntegerField(min_value=1, max_value=10)
        position = rfs.ChoiceField(choices=Position.choices)
        value = BaseField(required=True)

    type = rfs.CharField(default="visualizer")
    report = rfs.DictField(child=ReportSerializer(), allow_empty=True)

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
