# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from ..serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)
from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = VisualizerConfig
        fields = rfs.ALL_FIELDS
        list_serializer_class = PythonListConfigSerializer


class VisualizerReportSerializer(AbstractReportSerializer):
    name = rfs.SerializerMethodField()

    @classmethod
    def get_name(cls, instance: VisualizerReport):
        return instance.name or instance.config.pk

    class Meta:
        model = VisualizerReport
        fields = AbstractReportSerializer.Meta.fields
