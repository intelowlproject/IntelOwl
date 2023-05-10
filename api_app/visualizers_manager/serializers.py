# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.core.serializers import (
    AbstractConfigSerializer,
    AbstractListConfigSerializer,
    AbstractReportSerializer,
)

from .models import VisualizerConfig, VisualizerReport


class VisualizerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = VisualizerConfig
        fields = rfs.ALL_FIELDS
        list_serializer_class = AbstractListConfigSerializer


class VisualizerReportSerializer(AbstractReportSerializer):
    class Meta:
        model = VisualizerReport
        fields = AbstractReportSerializer.Meta.fields
