# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import re

import rest_email_auth.serializers
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from rest_framework import serializers as rfs
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from slack_sdk.errors import SlackApiError

from api_app.models import Job
from certego_saas.apps.user.serializers import (
    UserAccessSerializer as CertegoUserAccessSerializer,
)
from certego_saas.ext.upload import Slack
from certego_saas.models import User
from certego_saas.settings import certego_apps_settings
from intel_owl.consts import REGEX_PASSWORD

from .models import UserProfile

logger = logging.getLogger(__name__)

__all__ = [
    "UserAccessSerializer",
    "UserProfileSerializer",
    "RegistrationSerializer",
    "EmailVerificationSerializer",
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

    user = rfs.SerializerMethodField()
    access = rfs.SerializerMethodField()

    def get_user(self, obj: User) -> dict:
        data = super().get_user(obj)
        data["is_staff"] = obj.is_staff
        return data

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

    def validate_password(self, password):
        super().validate_password(password)

        if re.match(REGEX_PASSWORD, password):
            return password
        else:
            raise ValidationError("Invalid password")

    def create(self, validated_data):
        validated_data.pop("profile", None)
        validated_data["is_active"] = False
        user = None
        try:
            user = super().create(validated_data)

            # update profile object only if user object was actually saved
            if getattr(user, "pk", None):
                self._profile_serializer.update(
                    user.profile, self._profile_serializer.data
                )
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
        user = self._confirmation.email.user
        with transaction.atomic():
            super().save()

        # Send msg on slack
        if (
            certego_apps_settings.SLACK_TOKEN
            and certego_apps_settings.DEFAULT_SLACK_CHANNEL
        ):
            userprofile = user.user_profile
            user_admin_link = (
                f"{settings.WEB_CLIENT_URL}/admin/certego_saas_user/user/{user.pk}"
            )
            userprofile_admin_link = (
                f"{settings.WEB_CLIENT_URL}"
                f"/admin/authentication/userprofile/{userprofile.pk}"
            )
            slack = Slack()
            try:
                slack.send_message(
                    title="Newly registered user!!",
                    body=(
                        f"- User(#{user.pk}, {user.username},"
                        f"{user.email}, <{user_admin_link} |admin link>)\n"
                        f"- UserProfile({userprofile.company_name},"
                        f"{userprofile.company_role}, )"
                        f"<{userprofile_admin_link} |admin link>)"
                    ),
                    channel=certego_apps_settings.DEFAULT_SLACK_CHANNEL,
                )
            except SlackApiError as exc:
                slack.log.error(
                    f"Slack message failed for user(#{user.pk}) with error: {str(exc)}"
                )


class LoginSerializer(AuthTokenSerializer):
    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except rfs.ValidationError as exc:
            try:
                user = User.objects.get(username=attrs["username"])
            except User.DoesNotExist:
                # we do not want to leak info
                # so just raise the original exception
                raise exc
            else:
                # custom error messages
                if not user.is_active:
                    if user.is_email_verified is False:
                        exc.detail = "Your account is pending email verification."
                    elif user.approved is None:
                        exc.detail = "Your account is pending activation by our team."
                    elif user.approved is False:
                        exc.detail = "Your account was declined."
                    logger.info(
                        f"User {user} is not active. Error message: {exc.detail}"
                    )
            # else
            raise exc


class TokenSerializer(rfs.ModelSerializer):
    class Meta:
        model = Token
        fields = [
            "key",
            "created",
        ]
        read_only_fields = [
            "key",
            "created",
        ]

    def validate(self, data):
        user = self.context["user"]
        if Token.objects.filter(user=user).exists():
            raise rfs.ValidationError("An API token was already issued to you.")
        data["user"] = user
        return data
