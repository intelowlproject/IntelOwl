# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from .models import AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    class Meta:
        model = AnalyzerReport
        fields = "__all__"


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `analyzer_config.json`.
    """

    CONFIG_FILE_NAME = "analyzer_config.json"
    TYPE_CHOICES = (
        ("file", "file"),
        ("observable", "observable"),
    )
    HASH_CHOICES = (
        ("md5", "md5"),
        ("sha256", "sha256"),
    )

    # Required fields
    type = rfs.ChoiceField(required=True, choices=TYPE_CHOICES)
    external_service = rfs.BooleanField(required=True)
    # Optional Fields
    leaks_info = rfs.BooleanField(required=False)
    run_hash = rfs.BooleanField(required=False)
    run_hash_type = rfs.ChoiceField(required=False, choices=HASH_CHOICES)
    supported_filetypes = rfs.ListField(required=False)
    not_supported_filetypes = rfs.ListField(required=False)
    observable_supported = rfs.ListField(required=False)
