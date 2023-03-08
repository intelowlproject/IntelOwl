# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer, AbstractReportSerializer

from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(AbstractReportSerializer):
    """
    AnalyzerReport model's serializer.
    """

    class Meta:
        model = AnalyzerReport
        exclude = AbstractReportSerializer.Meta.exclude


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        fields = rfs.ALL_FIELDS
