# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import List

from rest_framework import serializers

from .base import ToolResultSerializer
from .job import JobToolSerializer


def flatten_errors(errors) -> List[str]:
    """Flatten DRF's ``{field: [msg, ...]}`` error dict into a flat ``list[str]``.

    Shared by the analyze_observable tool (preview validation) and the confirm endpoint
    (launch validation): the reused ObservableAnalysisSerializer reports failures as nested
    ValidationError dicts; callers only need a flat list of messages.
    """
    if isinstance(errors, dict):
        flat = []
        for field_name, messages in errors.items():
            if isinstance(messages, (list, tuple)):
                flat.extend(f"{field_name}: {message}" for message in messages)
            else:
                flat.append(f"{field_name}: {messages}")
        return flat
    if isinstance(errors, (list, tuple)):
        return [str(message) for message in errors]
    return [str(errors)]


class AnalysisPlanSerializer(serializers.Serializer):
    """What a confirmed analyze_observable call would launch (preview, no side effects)."""

    observable_name = serializers.CharField()
    classification = serializers.CharField()
    tlp = serializers.CharField()
    playbook = serializers.CharField(allow_null=True)
    analyzers = serializers.ListField(child=serializers.CharField())
    connectors = serializers.ListField(child=serializers.CharField())
    skipped = serializers.ListField(child=serializers.CharField())


class AnalyzeObservableResultSerializer(ToolResultSerializer):
    """Envelope for the analyze_observable tool, which now ONLY previews.

    `plan` is what a confirmed run would do; `pending_id` is the one-time token the user's
    Confirm button posts to the launch endpoint. The tool never launches an analysis itself.
    """

    plan = AnalysisPlanSerializer(allow_null=True)
    pending_id = serializers.CharField(allow_null=True)


class ConfirmAnalysisResultSerializer(serializers.Serializer):
    """Response of the analyze-confirm endpoint: the launched (or dedup-reused) job."""

    errors = serializers.ListField(child=serializers.CharField())
    reused = serializers.BooleanField()
    job = JobToolSerializer(allow_null=True)
