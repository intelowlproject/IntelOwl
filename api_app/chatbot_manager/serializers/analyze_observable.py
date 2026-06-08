# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers

from .base import ToolResultSerializer
from .job import JobToolSerializer


class AnalysisPlanSerializer(serializers.Serializer):
    """What a confirmed analyze_observable call would launch (preview, no side effects).

    Declared as a serializer (not a free-form dict) so the plan's shape is enforced and documented in
    one place; the tool feeds it the computed values on the confirm=False path.
    """

    observable_name = serializers.CharField()
    classification = serializers.CharField()
    tlp = serializers.CharField()
    playbook = serializers.CharField(allow_null=True)
    analyzers = serializers.ListField(child=serializers.CharField())
    connectors = serializers.ListField(child=serializers.CharField())
    # plugins dropped by TLP / not runnable for the user (the serializer's filter_warnings)
    skipped = serializers.ListField(child=serializers.CharField())


class AnalyzeObservableResultSerializer(ToolResultSerializer):
    """Envelope for the analyze_observable action tool.

    Two-phase contract: on the preview call `confirmation_required` is True and `plan` carries what
    would run; on the confirmed call `job` carries the launched -- or, on platform dedup, the reused
    recent -- Job, and `reused` says which it is.
    """

    confirmation_required = serializers.BooleanField()
    # True when a confirmed call returned an existing recent job (platform dedup) instead of a new one.
    reused = serializers.BooleanField()
    plan = AnalysisPlanSerializer(allow_null=True)
    job = JobToolSerializer(allow_null=True)  # reuse the existing compact, PII-free Job view
