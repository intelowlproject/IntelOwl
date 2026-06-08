# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers

from .base import ToolResultSerializer
from .job import JobToolSerializer


class AnalyzeObservableResultSerializer(ToolResultSerializer):
    """Envelope for the analyze_observable action tool.

    Two-phase contract: on the preview call `confirmation_required` is True and `plan` carries the
    computed `_AnalysisPlan` (what a confirmed call would launch); on the confirmed call `job` carries
    the created Job and the other two are null/false.
    """

    confirmation_required = serializers.BooleanField()
    plan = serializers.DictField(allow_null=True)
    job = JobToolSerializer(allow_null=True)  # reuse the existing compact, PII-free Job view
