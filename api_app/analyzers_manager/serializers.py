# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer

from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

    type = rfs.CharField(default="analyzer")

    class Meta:
        model = AnalyzerReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
            "end_time",
            "runtime_configuration",
            "type",
            "parent_playbook",
        )


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        fields = rfs.ALL_FIELDS
