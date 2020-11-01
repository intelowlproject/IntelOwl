import json

from django.contrib.auth.models import Group
from rest_framework import serializers
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin

from api_app.models import Job, Tag


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
        )

    tags = TagSerializer(many=True, read_only=True)
    process_time = serializers.SerializerMethodField()
    no_of_analyzers_executed = serializers.SerializerMethodField()

    def get_process_time(self, obj: Job):
        if not obj.finished_analysis_time:
            return None
        t = obj.finished_analysis_time - obj.received_request_time
        return round(t.total_seconds(), 2)

    def get_no_of_analyzers_executed(self, obj: Job):
        if obj.run_all_available_analyzers:
            return "all available analyzers"
        n1 = len(obj.analyzers_to_execute)
        n2 = len(obj.analyzers_requested)
        return f"{n1}/{n2}"


class JobSerializer(ObjectPermissionsAssignmentMixin, serializers.ModelSerializer):
    """
    Job model's serializer.
    Used for create(), retrieve()
    """

    tags = TagSerializer(many=True, read_only=True)
    tags_id = serializers.PrimaryKeyRelatedField(
        many=True, write_only=True, queryset=Tag.objects.all()
    )

    class Meta:
        model = Job
        fields = "__all__"
        extra_kwargs = {"file": {"write_only": True}}

    def get_permissions_map(self, created):
        """
        'view' permission is applied to all the groups the requesting user belongs to
        if private is True.
        """
        rqst = self.context["request"]
        if rqst.data.get("private", False):
            grps = rqst.user.groups.all()
        else:
            grps = Group.objects.all()

        return {
            "view_job": [*grps],
        }

    def validate(self, data):
        # check and validate runtime_configuration
        runtime_conf = data.get("runtime_configuration", {})
        if runtime_conf and isinstance(runtime_conf, list):
            runtime_conf = json.loads(runtime_conf[0])
        data["runtime_configuration"] = runtime_conf
        return data

    def create(self, validated_data):
        tags = validated_data.pop("tags_id", None)
        job = Job.objects.create(**validated_data)
        if tags:
            job.tags.set(tags)

        return job
