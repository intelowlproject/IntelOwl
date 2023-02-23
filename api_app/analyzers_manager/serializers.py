# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.core.exceptions import ValidationError
from django.utils.module_loading import import_string
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer

from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

    type = rfs.CharField(default="analyzer")

    class Meta:
        model = AnalyzerReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
            "end_time",
            "runtime_configuration",
            "type",
            "parent_playbook",
        )


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        fields = rfs.ALL_FIELDS

    def validate_python_path(self, python_path: str):
        return python_path

    def validate(self, attrs):
        attrs = super().validate(attrs)
        try:
            import_string(
                f"{self.Meta.model.python_path(attrs['type'])}.{attrs['python_path']}"
            )
        except ImportError:
            raise ValidationError(f"Unable to import {attrs['python_path']}")
        else:
            return attrs
