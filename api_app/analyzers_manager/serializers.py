# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ..serializers import (
    AbstractReportBISerializer,
    AbstractReportSerializer,
    CrontabScheduleSerializer,
    PeriodicTaskSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(AbstractReportSerializer):
    class Meta:
        model = AnalyzerReport
        fields = AbstractReportSerializer.Meta.fields
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class


class AnalyzerReportBISerializer(AbstractReportBISerializer):
    class Meta:
        model = AnalyzerReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class


class AnalyzerConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class AnalyzerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    update_schedule = CrontabScheduleSerializer(read_only=True)
    update_task = PeriodicTaskSerializer(read_only=True)

    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
