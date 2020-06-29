from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from api_app.models import Job, Tag
from intel_owl.settings import SIMPLE_JWT as jwt_settings


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = "__all__"


class JobSerializer(serializers.ModelSerializer):
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
        extra_kwargs = {"tags": {"required": False}}

    def create(self, validated_data):
        tags = validated_data.pop("tags_id", None)
        job = Job.objects.create(**validated_data)
        if tags:
            job.tags.set(tags)

        return job


class JobListSerializer(serializers.ModelSerializer):
    """
    Job model's list serializer.
    Used for list()
    """

    tags = TagSerializer(many=True, read_only=True)

    class Meta:
        model = Job
        exclude = ("analysis_reports", "errors")


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
