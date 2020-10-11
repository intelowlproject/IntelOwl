import json

from django.contrib.auth.models import Group
from rest_framework import serializers
from rest_framework_guardian.serializers import ObjectPermissionsAssignmentMixin
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from api_app.models import Job, Tag
from intel_owl.settings import SIMPLE_JWT as jwt_settings


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


class TokenRefreshPatchedSerializer(serializers.Serializer):
    """
    SimpleJWT's Custom RefreshToken serializer\n
    Issue: https://github.com/SimpleJWT/django-rest-framework-simplejwt/issues/25
    Patched TokenRefresh serializer so it
    stores the new refresh token to the list of Outstanding tokens immediately
    """

    refresh = serializers.CharField()

    def validate(self, attrs):
        # wrap the given refresh token as a RefreshToken object
        refresh = RefreshToken(attrs["refresh"])
        # create response data
        data = {"access": str(refresh.access_token)}

        if jwt_settings["ROTATE_REFRESH_TOKENS"]:
            blacklisted_token = None
            if jwt_settings["BLACKLIST_AFTER_ROTATION"]:
                try:
                    # Attempt to blacklist the given refresh token
                    blacklisted_token, _ = refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            # rotate refresh token
            refresh.set_jti()
            if refresh.get("client", False) == "pyintelowl":
                refresh.set_exp(
                    lifetime=jwt_settings.get("PYINTELOWL_TOKEN_LIFETIME", None)
                )
            else:
                refresh.set_exp()

            data["refresh"] = str(refresh)

            # PATCHED - Create Outstanding Token in the db
            if blacklisted_token:
                user = blacklisted_token.token.user
                if user:
                    OutstandingToken.objects.create(
                        user=user,
                        jti=refresh.payload["jti"],
                        token=str(refresh),
                        created_at=refresh.current_time,
                        expires_at=datetime_from_epoch(refresh["exp"]),
                    )

        return data
