# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from ..data_model_manager.serializers import DataModelRelatedField
from ..models import PythonModule
from ..serializers.plugin import (
    ParameterSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from ..serializers.report import AbstractReportBISerializer, AbstractReportSerializer
from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(AbstractReportSerializer):
    data_model = DataModelRelatedField(read_only=True)

    class Meta:
        model = AnalyzerReport
        fields = AbstractReportSerializer.Meta.fields + ["data_model"]
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class


class AnalyzerReportBISerializer(AbstractReportBISerializer):
    class Meta:
        model = AnalyzerReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class


class AnalyzerConfigSerializer(PythonConfigSerializer):
    python_module = rfs.SlugRelatedField(queryset=PythonModule.objects.all(), slug_field="module")

    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class

    def to_representation(self, instance):
        result = super().to_representation(instance)
        parameters = ParameterSerializer(instance.parameters, many=True)
        result["parameters"] = parameters.data
        return result


class AnalyzerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
