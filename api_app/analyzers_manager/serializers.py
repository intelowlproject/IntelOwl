# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from ..serializers import (
    AbstractReportSerializer,
    CrontabScheduleSerializer,
    PeriodicTaskSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)
from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(AbstractReportSerializer):
    """
    AnalyzerReport model's serializer.
    """

    class Meta:
        model = AnalyzerReport
        fields = AbstractReportSerializer.Meta.fields


class AnalyzerConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        exclude = ["disabled_in_organizations"]
        list_serializer_class = PythonListConfigSerializer


class AnalyzerConfigSerializerForMigration(AnalyzerConfigSerializer):
    update_schedule = CrontabScheduleSerializer(read_only=True)
    update_task = PeriodicTaskSerializer(read_only=True)

    class Meta:
        model = AnalyzerConfig
        fields = rfs.ALL_FIELDS
        list_serializer_class = PythonListConfigSerializer
