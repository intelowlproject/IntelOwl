# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from ..models import PythonModule
from ..serializers.plugin import (
    PluginConfigSerializer,
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
    plugin_config = rfs.DictField(write_only=True, required=False)
    python_module = rfs.SlugRelatedField(
        queryset=PythonModule.objects.all(), slug_field="module"
    )

    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializer.Meta.exclude
        list_serializer_class = PythonConfigSerializer.Meta.list_serializer_class

    def create(self, validated_data):
        plugin_config = validated_data.pop("plugin_config", {})
        pc = super().create(validated_data)

        # create plugin config
        if plugin_config:
            plugin_config_serializer = PluginConfigSerializer(
                data=plugin_config, context={"request": self.context["request"]}
            )
            plugin_config_serializer.is_valid(raise_exception=True)
            plugin_config_serializer.save()
        return pc


class AnalyzerConfigSerializerForMigration(PythonConfigSerializerForMigration):
    class Meta:
        model = AnalyzerConfig
        exclude = PythonConfigSerializerForMigration.Meta.exclude
