# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from rest_framework import serializers

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig

from .models import ChatMessage, ChatSession


class AnalyzerReportToolSerializer(serializers.ModelSerializer):
    """Compact analyzer-report view used inside JobDetailToolSerializer."""

    name = serializers.CharField(source="config.name", read_only=True)
    report = serializers.SerializerMethodField()

    class Meta:
        model = AnalyzerReport
        fields = ["name", "status", "report"]

    def get_report(self, obj: AnalyzerReport):
        # `report` is a JSONField (dict / list / scalar). Dicts pass through; anything else
        # is stringified and capped so a single large report can't blow up the LLM prompt.
        return obj.report if isinstance(obj.report, dict) else str(obj.report)[:500]


class JobToolSerializer(serializers.ModelSerializer):
    """Compact, LLM-facing Job view for search results (no user/PII fields)."""

    observable_name = serializers.CharField(source="analyzable.name", read_only=True)
    observable_classification = serializers.CharField(source="analyzable.classification", read_only=True)
    md5 = serializers.CharField(source="analyzable.md5", read_only=True)
    analyzers_to_execute = serializers.SlugRelatedField(slug_field="name", many=True, read_only=True)

    class Meta:
        model = Job
        fields = [
            "id",
            "observable_name",
            "observable_classification",
            "md5",
            "status",
            "tlp",
            "received_request_time",
            "finished_analysis_time",
            "analyzers_to_execute",
        ]


class JobDetailToolSerializer(JobToolSerializer):
    """Full Job view for get_job_details: adds tags, analyzer reports and errors/warnings."""

    tags = serializers.SlugRelatedField(slug_field="label", many=True, read_only=True)
    # output key stays `analyzer_reports` (like the public JobSerializer); the actual
    # reverse relation is `analyzerreports`.
    analyzer_reports = AnalyzerReportToolSerializer(many=True, read_only=True, source="analyzerreports")

    class Meta(JobToolSerializer.Meta):
        fields = JobToolSerializer.Meta.fields + [
            "process_time",
            "tags",
            "errors",
            "warnings",
            "analyzer_reports",
        ]


class ToolResultSerializer(serializers.Serializer):
    """Base envelope for agent-tool output: an always-present `errors` list plus a payload.

    A LangChain tool must return a string (it is fed back to the model as the ReAct
    Observation), so `to_json()` renders the serialized envelope to a JSON string.
    """

    errors = serializers.ListField(child=serializers.CharField(), default=list)

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2)


class SearchJobsResultSerializer(ToolResultSerializer):
    jobs = JobToolSerializer(many=True)


class JobDetailResultSerializer(ToolResultSerializer):
    job = JobDetailToolSerializer(allow_null=True)


class SummarizeJobResultSerializer(ToolResultSerializer):
    summary = serializers.CharField(allow_null=True)


class InvestigationToolSerializer(serializers.ModelSerializer):
    """Compact, LLM-facing Investigation view for list results (no owner/PII fields).

    Deliberately exposes only DB columns. `Investigation.tlp`, `.tags` and `.total_jobs`
    are @properties that each query the `jobs` relation, so including them here would fire
    extra queries for every row (N+1 across a list). Those aggregate fields are surfaced
    instead by `summarize_investigation` / `get_investigation_tree`, which operate on a
    single investigation where the cost is bounded.
    """

    class Meta:
        model = Investigation
        fields = ["id", "name", "status", "start_time", "end_time"]


class InvestigationsResultSerializer(ToolResultSerializer):
    investigations = InvestigationToolSerializer(many=True)


class InvestigationTreeResultSerializer(ToolResultSerializer):
    # The tree is assembled in Python (in the tool) to avoid the treebeard per-node N+1,
    # so the payload is already a plain nested dict; the envelope only JSON-serializes it.
    investigation = serializers.DictField(read_only=True, allow_null=True)


class SummarizeInvestigationResultSerializer(ToolResultSerializer):
    summary = serializers.CharField(allow_null=True)


class DataModelResultSerializer(ToolResultSerializer):
    # `data_model` is already produced by the model's own DRF serializer
    # (`BaseDataModel.serialize()`, polymorphic across Domain/IP/File), so the envelope
    # just carries that dict (empty `{}` when the job has no data model).
    data_model = serializers.DictField(read_only=True)


class AnalyzerConfigToolSerializer(serializers.ModelSerializer):
    """Compact, LLM-facing AnalyzerConfig view for list_analyzers (no owner/PII fields).

    `runnable` is read from a per-user queryset annotation (`annotate_runnable`): True means
    ready to run for the requesting user, False means org-disabled or not fully configured. It
    is a readiness flag, not a visibility filter -- the analyzer is listed either way.
    """

    # `observable_supported` is a ChoiceArrayField; DRF's ModelSerializer does not auto-map it,
    # so declare it explicitly (same approach as the heavy PlaybookConfigSerializer's `type`).
    observable_supported = serializers.ListField(child=serializers.CharField(), read_only=True)
    runnable = serializers.BooleanField(read_only=True)

    class Meta:
        model = AnalyzerConfig
        fields = ["name", "description", "type", "observable_supported", "maximum_tlp", "runnable"]


class PlaybookConfigToolSerializer(serializers.ModelSerializer):
    """Compact, LLM-facing PlaybookConfig view for recommend_playbook (no owner/PII fields)."""

    # `type` is a ChoiceArrayField of classifications; declare it explicitly (DRF doesn't auto-map
    # it). `analyzers`/`connectors` are M2M relations rendered as their names.
    type = serializers.ListField(child=serializers.CharField(), read_only=True)
    analyzers = serializers.SlugRelatedField(slug_field="name", many=True, read_only=True)
    connectors = serializers.SlugRelatedField(slug_field="name", many=True, read_only=True)

    class Meta:
        model = PlaybookConfig
        fields = ["name", "description", "type", "analyzers", "connectors"]


class ListAnalyzersResultSerializer(ToolResultSerializer):
    analyzers = AnalyzerConfigToolSerializer(many=True)


class RecommendPlaybookResultSerializer(ToolResultSerializer):
    playbooks = PlaybookConfigToolSerializer(many=True)


class ChatSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatSession
        fields = ["id", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class ChatMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ["id", "role", "content", "timestamp"]
        read_only_fields = ["id", "timestamp"]


class MessageRequestSerializer(serializers.Serializer):
    session_id = serializers.IntegerField(required=False, allow_null=True)
    message = serializers.CharField(max_length=4096)


class MessageResponseSerializer(serializers.Serializer):
    # Serializes the persisted assistant ChatMessage directly (no hand-built dict).
    session_id = serializers.IntegerField()
    response = serializers.CharField(source="content")
    message_id = serializers.IntegerField(source="id")
