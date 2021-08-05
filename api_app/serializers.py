# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from django.contrib.auth.models import Group
from rest_framework import serializers
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin

from api_app.models import Job, Tag
from .helpers import calculate_mimetype
from .analyzers_manager.serializers import AnalyzerReportSerializer
from .connectors_manager.serializers import ConnectorReportSerializer


__all__ = [
    "TagSerializer",
    "JobListSerializer",
    "JobSerializer",
    "FileAnalysisSerializer",
    "ObservableAnalysisSerializer",
]


class TagSerializer(ObjectPermissionsAssignmentMixin, serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = "__all__"

    def get_permissions_map(self, created):
        """
        'change' and 'delete' permission
        is applied to all the groups the requesting user belongs to.
        But everyone has 'view' permission.
        """
        current_user = self.context["request"].user
        user_grps = [*current_user.groups.all()]

        return {
            "change_tag": user_grps,
            "delete_tag": user_grps,
        }


class JobListSerializer(serializers.ModelSerializer):
    """
    Job model's list serializer.
    Used for list()
    """

    class Meta:
        model = Job
        fields = (
            "id",
            "is_sample",
            "observable_name",
            "observable_classification",
            "file_name",
            "file_mimetype",
            "status",
            "tags",
            "process_time",
            "no_of_analyzers_executed",
            "no_of_connectors_executed",
        )

    tags = TagSerializer(many=True, read_only=True)
    process_time = serializers.SerializerMethodField()
    no_of_analyzers_executed = serializers.SerializerMethodField()
    no_of_connectors_executed = serializers.SerializerMethodField()

    def get_process_time(self, obj: Job):
        if not obj.finished_analysis_time:
            return None
        t = obj.finished_analysis_time - obj.received_request_time
        return round(t.total_seconds(), 2)

    def get_no_of_analyzers_executed(self, obj: Job) -> str:
        if obj.run_all_available_analyzers:
            return "all available analyzers"
        n1 = len(obj.analyzers_to_execute)
        n2 = len(obj.analyzers_requested)
        return f"{n1}/{n2}"

    def get_no_of_connectors_executed(self, obj: Job) -> str:
        n1 = obj.connector_reports.count()
        n2 = len(obj.connectors_to_execute)
        return f"{n1}/{n2}"


class JobSerializer(serializers.ModelSerializer):
    """
    Job model's serializer.
    Used for retrieve()
    """

    tags = TagSerializer(many=True, read_only=True)
    analyzer_reports = AnalyzerReportSerializer(many=True, read_only=True)
    connector_reports = ConnectorReportSerializer(many=True, read_only=True)

    class Meta:
        model = Job
        exclude = ("file",)


class _AbstractJobCreateSerializer(
    serializers.ModelSerializer,
    ObjectPermissionsAssignmentMixin,
):
    """
    Base Serializer for Job create().
    """

    tags_id = serializers.PrimaryKeyRelatedField(
        many=True, write_only=True, queryset=Tag.objects.all()
    )
    runtime_configuration = serializers.JSONField(
        required=False, default={}, write_only=True
    )
    analyzers_requested = serializers.ListField(default=list)
    run_all_available_analyzers = serializers.BooleanField(default=False)
    private = serializers.BooleanField(default=False)

    def get_permissions_map(self, created) -> dict:
        """
        * 'view' permission is applied to all the groups the requesting user belongs to
        if private is True.
        * 'delete' permission is only given to the user who created the job
        * 'change' permission is given to
        """
        current_user = self.context["request"].user
        usr_groups = current_user.groups.all()
        if self.validated_data["private"]:
            view_grps = usr_groups
        else:
            view_grps = Group.objects.all()

        return {
            "view_job": [*view_grps],
            "delete_job": [*usr_groups],
            "change_job": [*usr_groups],
        }

    def validate(self, data) -> dict:
        # check and validate runtime_configuration
        runtime_conf = data.get("runtime_configuration", {})
        if runtime_conf and isinstance(runtime_conf, list):
            runtime_conf = json.loads(runtime_conf[0])
        data["runtime_configuration"] = runtime_conf

        run_all_available_analyzers = data["run_all_available_analyzers"]
        analyzers_requested = data["analyzers_requested"]
        if not run_all_available_analyzers and not len(analyzers_requested):
            raise serializers.ValidationError(
                "Atleast one of `analyzers_requested` "
                "and `run_all_available_analyzers` should be provided."
            )

        if run_all_available_analyzers and len(analyzers_requested):
            raise serializers.ValidationError(
                "`analyzers_requested` and `run_all_available_analyzers`"
                "cannot be used together."
            )

        return data

    def create(self, validated_data) -> Job:
        # fields `tags_id` are not there in `Job` model.
        validated_data.pop("private", None)
        tags = validated_data.pop("tags_id", None)
        job = Job.objects.create(**validated_data)
        if tags:
            job.tags.set(tags)

        return job


class FileAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    Job model's serializer for File Analysis.
    Used for create()
    """

    file = serializers.FileField(required=True)
    file_name = serializers.CharField(required=True)
    file_mimetype = serializers.HiddenField(default=None)
    is_sample = serializers.HiddenField(default=True)

    class Meta:
        model = Job
        fields = (
            "id",
            "source",
            "is_sample",
            "md5",
            "force_privacy",
            "disable_external_analyzers",
            "file",
            "file_name",
            "file_mimetype",
            "run_all_available_analyzers",
            "runtime_configuration",
            "analyzers_requested",
            "tags_id",
            "private",
        )

    def validate(self, attrs):
        super(FileAnalysisSerializer, self).validate(attrs)
        attrs["file_mimetype"] = calculate_mimetype(attrs["file"], attrs["file_name"])
        return attrs


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    Job model's serializer for Observable Analysis.
    Used for create()
    """

    observable_name = serializers.CharField(required=True)
    observable_classification = serializers.CharField(required=True)
    is_sample = serializers.HiddenField(default=False)

    class Meta:
        model = Job
        fields = (
            "id",
            "source",
            "is_sample",
            "md5",
            "force_privacy",
            "disable_external_analyzers",
            "observable_name",
            "observable_classification",
            "run_all_available_analyzers",
            "runtime_configuration",
            "analyzers_requested",
            "tags_id",
            "private",
        )
