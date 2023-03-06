# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer

from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = VisualizerConfig
        fields = rfs.ALL_FIELDS


class VisualizerReportSerializer(rfs.ModelSerializer):

    type = rfs.CharField(default="visualizer")

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
