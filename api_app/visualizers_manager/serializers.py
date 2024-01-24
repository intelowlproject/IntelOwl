# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from ..playbooks_manager.models import PlaybookConfig
from ..serializers import (
    AbstractReportBISerializer,
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonConfigSerializerForMigration,
)
from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(PythonConfigSerializer):
    playbooks = rfs.SlugRelatedField(
        many=True, queryset=PlaybookConfig.objects.all(), slug_field="name"
    )

    class Meta:
        model = VisualizerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class


class VisualizerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = VisualizerConfig
        fields = PythonConfigSerializerForMigration.Meta.fields


class VisualizerReportSerializer(AbstractReportSerializer):
    name = rfs.SerializerMethodField()

    config = rfs.SlugRelatedField(
        queryset=VisualizerConfig.objects.all(), slug_field="name"
    )

    @classmethod
    def get_name(cls, instance: VisualizerReport):
        return instance.name or instance.config.pk

    class Meta:
        model = VisualizerReport
        fields = AbstractReportSerializer.Meta.fields + [
            "config",
        ]
        list_serializer_class = AbstractReportSerializer.Meta.list_serializer_class


class VisualizerReportBISerializer(AbstractReportBISerializer):
    name = rfs.SerializerMethodField()

    @classmethod
    def get_name(cls, instance: VisualizerReport):
        return instance.name or instance.config.pk

    class Meta:
        model = VisualizerReport
        fields = AbstractReportBISerializer.Meta.fields
        list_serializer_class = AbstractReportBISerializer.Meta.list_serializer_class
