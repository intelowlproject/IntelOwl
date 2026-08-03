# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.models import Job

from .base import ToolResultSerializer


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


class SearchJobsResultSerializer(ToolResultSerializer):
    jobs = JobToolSerializer(many=True)


class JobDetailResultSerializer(ToolResultSerializer):
    job = JobDetailToolSerializer(allow_null=True)


class AnalyzerVerdictSerializer(serializers.Serializer):
    """One analyzer's own evaluation, read from the DataModel its report produced."""

    name = serializers.CharField(read_only=True)
    evaluation = serializers.CharField(read_only=True)
    reliability = serializers.IntegerField(read_only=True)


class JobVerdictSerializer(serializers.Serializer):
    """IntelOwl's reconciled verdict on a job plus the evidence behind it.

    Mirrors the `JobEvaluation` dataclass (`chatbot_manager/evaluation.py`). `bucket` is the same
    word the DataModel visualizer badge shows; `reason` is set only when there is no verdict, so
    the model can explain the absence instead of inventing one.
    """

    bucket = serializers.CharField(read_only=True)
    evaluation = serializers.CharField(read_only=True, allow_null=True)
    reliability = serializers.IntegerField(read_only=True)
    headline = serializers.CharField(read_only=True)
    analyst_override = serializers.BooleanField(read_only=True)
    reason = serializers.CharField(read_only=True, allow_null=True)
    supporting = AnalyzerVerdictSerializer(many=True, read_only=True)
    contradicting = AnalyzerVerdictSerializer(many=True, read_only=True)
    silent = serializers.ListField(child=serializers.CharField(), read_only=True)
    silent_count = serializers.IntegerField(read_only=True)
    analyzers_considered = serializers.IntegerField(read_only=True)


class SummarizeJobResultSerializer(ToolResultSerializer):
    summary = serializers.CharField(allow_null=True)
    verdict = JobVerdictSerializer(allow_null=True)
