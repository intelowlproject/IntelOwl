# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from ..serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = VisualizerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class VisualizerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = VisualizerConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude


class VisualizerReportSerializer(AbstractReportSerializer):
    name = rfs.SerializerMethodField()

    @classmethod
    def get_name(cls, instance: VisualizerReport):
        return instance.name or instance.config.pk

    class Meta:
        model = VisualizerReport
        fields = AbstractReportSerializer.Meta.fields
