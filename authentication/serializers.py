# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import rest_email_auth.serializers
from django.db import DatabaseError, transaction
from rest_framework import serializers as rfs

from api_app.models import Job
from certego_saas.apps.user.serializers import (
    UserAccessSerializer as CertegoUserAccessSerializer,
)
from certego_saas.models import User

from .models import UserProfile

logger = logging.getLogger(__name__)

__all__ = [
    "UserAccessSerializer",
]


class _AccessSerializer(rfs.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "total_submissions",
            "month_submissions",
        )

    # User <-> Job stats
    total_submissions = rfs.SerializerMethodField()
    month_submissions = rfs.SerializerMethodField()

    @staticmethod
    def get_total_submissions(obj: User) -> int:
        return Job.user_total_submissions(obj)

    @staticmethod
    def get_month_submissions(obj: User) -> int:
        return Job.user_month_submissions(obj)


class UserAccessSerializer(CertegoUserAccessSerializer):
    class Meta:
        model = User
        fields = (
            "user",
            "access",
        )

    access = rfs.SerializerMethodField()

    @staticmethod
    def get_access(obj: User) -> dict:
        return _AccessSerializer(instance=obj).data


class UserProfileSerializer(rfs.ModelSerializer):
    class Meta:
        model = UserProfile
        exclude = ("user",)


class RegistrationSerializer(rest_email_auth.serializers.RegistrationSerializer):
    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "is_active",
            "profile",
        )
        extra_kwargs = {
            "password": {
                "style": {"input_type": "password"},
                "write_only": True,
            },
            "first_name": {
                "required": True,
                "write_only": True,
            },
            "last_name": {
                "required": True,
                "write_only": True,
            },
        }

    profile = UserProfileSerializer(write_only=True)
    is_active = rfs.BooleanField(default=False, read_only=True)

    def validate_profile(self, profile):

        logger.info(f"{profile}")

        self._profile_serializer = UserProfileSerializer(data=profile)
        self._profile_serializer.is_valid(raise_exception=True)
        return profile

    def create(self, validated_data):
        validated_data.pop("profile", None)
        validated_data["is_active"] = False
        user = None
        try:
            user = super().create(validated_data)

            # save profile object only if user object was actually saved
            if getattr(user, "pk", None):
                self._profile_serializer.save(user=user)
                user.refresh_from_db()
        except DatabaseError:
            transaction.rollback()
        return user


class EmailVerificationSerializer(
    rest_email_auth.serializers.EmailVerificationSerializer
):
    def validate_key(self, key):
        try:
            return super().validate_key(key)
        except rfs.ValidationError as exc:
            # custom error messages
            err_str = str(exc.detail)
            if "invalid" in err_str:
                exc.detail = (
                    "The provided verification key"
                    " is invalid or your email address is already verified."
                )
            if "expired" in err_str:
                exc.detail = (
                    "The provided verification key"
                    " has expired or your email address is already verified."
                )
            raise exc

    def save(self):
        """
        Confirm the email address matching the confirmation key.
        Then mark user as active.
        """
        # user = self._confirmation.email.user
        with transaction.atomic():
            super(EmailVerificationSerializer, self).save()
            # FIXME: https://github.com/certego/Dragonfly/issues/447
            # Automated verification will be enabled in Beta.
            # user.is_active = True
            # user.save(update_fields=("is_active",))
