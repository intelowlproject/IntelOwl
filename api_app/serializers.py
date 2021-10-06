# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

from django.contrib.auth.models import Group
from rest_framework import serializers
from rest_flex_fields import FlexFieldsModelSerializer
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin

from api_app.models import Job, TLP, Tag
from .helpers import (
    calculate_mimetype,
    calculate_observable_classification,
    calculate_md5,
)
from .analyzers_manager.serializers import AnalyzerReportSerializer
from .connectors_manager.serializers import ConnectorReportSerializer

logger = logging.getLogger(__name__)


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


class JobAvailabilitySerializer(serializers.ModelSerializer):
    """
    Serializer for ask_analysis_availability
    """

    class Meta:
        model = Job
        fields = "__all__"

    md5 = serializers.CharField(max_length=128, required=True)
    analyzers = serializers.ListField(default=list)
    running_only = serializers.BooleanField(default=False)


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

    def get_process_time(self, obj: Job) -> float:
        if not obj.finished_analysis_time:
            return None
        t = obj.finished_analysis_time - obj.received_request_time
        return round(t.total_seconds(), 2)

    def get_no_of_analyzers_executed(self, obj: Job) -> str:
        n1 = len(obj.analyzers_to_execute) or "-"
        n2 = len(obj.analyzers_requested) or "-"
        return f"{n1}/{n2}"

    def get_no_of_connectors_executed(self, obj: Job) -> str:
        n1 = len(obj.connectors_to_execute) or "-"
        n2 = len(obj.connectors_requested) or "-"
        return f"{n1}/{n2}"


class JobSerializer(FlexFieldsModelSerializer):
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
    connectors_requested = serializers.ListField(default=list)

    def get_permissions_map(self, created) -> dict:
        """
        * 'view' permission is applied to all the groups the requesting user belongs to
        if job is private (tlp - RED, AMBER).
        * 'delete' permission is only given to the user who created the job
        * 'change' permission is given to
        """
        current_user = self.context["request"].user
        usr_groups = current_user.groups.all()
        tlp = self.validated_data.get("tlp", TLP.WHITE).upper()
        if tlp == TLP.RED or tlp == TLP.AMBER:
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

        return data

    def create(self, validated_data) -> Job:
        # fields `tags_id` are not there in `Job` model.
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
    md5 = serializers.CharField(required=False)
    is_sample = serializers.HiddenField(default=True)

    class Meta:
        model = Job
        fields = (
            "id",
            "source",
            "is_sample",
            "md5",
            "tlp",
            "file",
            "file_name",
            "file_mimetype",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "tags_id",
        )

    def validate(self, attrs):
        super(FileAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        attrs["file_mimetype"] = calculate_mimetype(attrs["file"], attrs["file_name"])
        if not attrs.get("md5", ""):
            attrs["md5"] = calculate_md5(attrs["file"])
        logger.debug(f"after attrs: {attrs}")
        return attrs


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    Job model's serializer for Observable Analysis.
    Used for create()
    """

    observable_name = serializers.CharField(required=True)
    observable_classification = serializers.CharField(required=False)
    md5 = serializers.CharField(required=False)
    is_sample = serializers.HiddenField(default=False)

    class Meta:
        model = Job
        fields = (
            "id",
            "source",
            "is_sample",
            "md5",
            "tlp",
            "observable_name",
            "observable_classification",
            "runtime_configuration",
            "analyzers_requested",
            "connectors_requested",
            "tags_id",
        )

    def validate(self, attrs):
        super(ObservableAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        attrs["observable_name"] = attrs["observable_name"].lower()
        if not attrs.get("observable_classification", ""):
            attrs["observable_classification"] = calculate_observable_classification(
                attrs["observable_name"]
            )
        if not attrs.get("md5", ""):
            attrs["md5"] = calculate_md5(attrs["observable_name"])
        logger.debug(f"after attrs: {attrs}")
        return attrs
