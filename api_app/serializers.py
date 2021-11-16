# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

from django.contrib.auth.models import Group
from rest_flex_fields import FlexFieldsModelSerializer
from rest_framework import serializers
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin

from api_app.models import TLP, Job, Tag

from .analyzers_manager.serializers import AnalyzerReportSerializer
from .connectors_manager.serializers import ConnectorReportSerializer
from .helpers import (
    calculate_md5,
    calculate_mimetype,
    calculate_observable_classification,
    gen_random_colorhex,
)

logger = logging.getLogger(__name__)


__all__ = [
    "TagSerializer",
    "JobAvailabilitySerializer",
    "JobListSerializer",
    "JobSerializer",
    "FileAnalysisSerializer",
    "ObservableAnalysisSerializer",
    "AnalysisResponseSerializer",
]


class TagSerializer(ObjectPermissionsAssignmentMixin, serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = serializers.ALL_FIELDS

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
        fields = serializers.ALL_FIELDS

    md5 = serializers.CharField(max_length=128, required=True)
    analyzers = serializers.ListField(default=list)
    running_only = serializers.BooleanField(default=False, required=False)
    minutes_ago = serializers.IntegerField(default=None, required=False)


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

    tags_labels = serializers.ListField(default=list)
    runtime_configuration = serializers.JSONField(
        required=False, default={}, write_only=True
    )
    analyzers_requested = serializers.ListField(default=list)
    connectors_requested = serializers.ListField(default=list)
    md5 = serializers.HiddenField(default=None)

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

    def validate(self, attrs: dict) -> dict:
        # check and validate runtime_configuration
        runtime_conf = attrs.get("runtime_configuration", {})
        if runtime_conf and isinstance(runtime_conf, list):
            runtime_conf = json.loads(runtime_conf[0])
        attrs["runtime_configuration"] = runtime_conf

        return attrs

    def create(self, validated_data: dict) -> Job:
        # create ``Tag`` objects from tags_labels
        tags_labels = validated_data.pop("tags_labels", None)
        tags = [
            Tag.objects.get_or_create(
                label=label, defaults={"color": gen_random_colorhex()}
            )[0]
            for label in tags_labels
        ]

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
    file_mimetype = serializers.CharField(required=False)
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
            "tags_labels",
        )

    def validate(self, attrs: dict) -> dict:
        attrs = super(FileAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        # calculate ``file_mimetype``
        attrs["file_mimetype"] = calculate_mimetype(attrs["file"], attrs["file_name"])
        # calculate ``md5``
        file_obj = attrs["file"].file
        file_obj.seek(0)
        file_buffer = file_obj.read()
        attrs["md5"] = calculate_md5(file_buffer)
        logger.debug(f"after attrs: {attrs}")
        return attrs


class ObservableAnalysisSerializer(_AbstractJobCreateSerializer):
    """
    Job model's serializer for Observable Analysis.
    Used for create()
    """

    observable_name = serializers.CharField(required=True)
    observable_classification = serializers.CharField(required=False)
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
            "tags_labels",
        )

    def validate(self, attrs: dict) -> dict:
        attrs = super(ObservableAnalysisSerializer, self).validate(attrs)
        logger.debug(f"before attrs: {attrs}")
        # force lowercase in ``observable_name``.
        # Ref: https://github.com/intelowlproject/IntelOwl/issues/658
        attrs["observable_name"] = attrs["observable_name"].lower()
        # calculate ``observable_classification``
        if not attrs.get("observable_classification", None):
            attrs["observable_classification"] = calculate_observable_classification(
                attrs["observable_name"]
            )
        # calculate ``md5``
        attrs["md5"] = calculate_md5(attrs["observable_name"].encode("utf-8"))
        logger.debug(f"after attrs: {attrs}")
        return attrs


class AnalysisResponseSerializer(serializers.Serializer):
    job_id = serializers.IntegerField()
    status = serializers.CharField()
    warnings = serializers.ListField()
    analyzers_running = serializers.ListField()
    connectors_running = serializers.ListField()
