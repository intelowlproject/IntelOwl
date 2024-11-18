# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from ..models import PythonModule
from ..serializers.plugin import (
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from ..serializers.report import AbstractReportBISerializer, AbstractReportSerializer
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
    python_module = rfs.SlugRelatedField(
        queryset=PythonModule.objects.all(), slug_field="module"
    )

    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class AnalyzerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
