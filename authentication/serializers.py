# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""This module contains various serializers used in the authentication process
for the IntelOwl project. These serializers handle user access, user profile,
registration, email verification, login, and token generation.
"""

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
from certego_saas.apps.user.serializers import UserSerializer
from certego_saas.ext.upload import Slack
from certego_saas.models import User
from certego_saas.settings import certego_apps_settings
from intel_owl.consts import REGEX_PASSWORD

from .models import UserProfile

logger = logging.getLogger(__name__)

__all__ = [
    "UserAccessSerializer",
    "UserProfileSerializer",
    "ProfileSerializer",
    "RegistrationSerializer",
    "EmailVerificationSerializer",
]


class _AccessSerializer(rfs.ModelSerializer):
    """
    Serializer to get user job statistics such as total and monthly submissions.

    Attributes:
        total_submissions (int): Total number of submissions by the user.
        month_submissions (int): Number of submissions by the user in the current month.
    """

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
    """
    Serializer to get user access details including staff status.

    Attributes:
        user (dict): User details including staff status.
        access (dict): Access details of the user.
    """

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


class HiddenUserSerializer(UserSerializer):
    """Serializer for user details with hidden password."""

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
            "is_active",
        )


class ProfileSerializer(rfs.ModelSerializer):
    """Serializer for the UserProfile model."""

    user = HiddenUserSerializer(read_only=True)

    class Meta:
        model = UserProfile
        exclude = ("id",)


class UserProfileSerializer(UserSerializer):
    """
    Serializer for the User model with nested UserProfile.

    This serializer includes the user's username and their associated profile.
    The profile field is read-only and is serialized using the ProfileSerializer.
    """

    profile = ProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ("username", "profile")  # used only in the final recursion get()


class RegistrationSerializer(rest_email_auth.serializers.RegistrationSerializer):
    """
    Serializer for user registration.

    Attributes:
        profile (UserProfileSerializer): Nested serializer for user profile.
        is_active (bool): Indicates if the user is active.
    """

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

    profile = ProfileSerializer(write_only=True)
    is_active = rfs.BooleanField(default=False, read_only=True)

    def validate_profile(self, profile):
        """
        Validate the user profile.

        Args:
            profile (dict): Profile data.

        Returns:
            dict: Validated profile data.
        """
        logger.info(f"{profile}")

        self._profile_serializer = ProfileSerializer(data=profile)
        self._profile_serializer.is_valid(raise_exception=True)
        return profile

    def validate_password(self, password):
        """
        Validate the user's password against a regex pattern.

        Args:
            password (str): The password to validate.

        Returns:
            str: The validated password.

        Raises:
            ValidationError: If the password does not match the regex pattern.
        """
        super().validate_password(password)

        if re.match(REGEX_PASSWORD, password):
            return password
        else:
            raise ValidationError("Invalid password")

    def create(self, validated_data):
        """
        Create a new user and handle profile updates.

        This method creates a new user with the provided validated data and sets
        the user as inactive by default. It also handles the creation and update
        of the associated user profile.

        Args:
            validated_data (dict): The validated data for creating the user.

        Returns:
            User: The created user instance.

        Raises:
            DatabaseError: If there is an error saving the user or profile data to the database.
        """
        validated_data.pop("profile", None)
        validated_data["is_active"] = False
        user = None
        try:
            user = super().create(validated_data)

            # update profile object only if user object was actually saved
            if getattr(user, "pk", None):
                self._profile_serializer.update(user.profile, self._profile_serializer.data)
                user.refresh_from_db()
        except DatabaseError:
            transaction.rollback()
        return user


class EmailVerificationSerializer(rest_email_auth.serializers.EmailVerificationSerializer):
    """
    Serializer for email verification.

    Customizes the error messages for invalid or expired verification keys.
    """

    def validate_key(self, key):
        """
        Validate the email verification key.

        Args:
            key (str): The verification key to validate.

        Returns:
            str: The validated key.

        Raises:
            ValidationError: If the key is invalid or expired.
        """
        try:
            return super().validate_key(key)
        except rfs.ValidationError as exc:
            # custom error messages
            err_str = str(exc.detail)
            if "invalid" in err_str:
                exc.detail = (
                    "The provided verification key is invalid or your email address is already verified."
                )
            if "expired" in err_str:
                exc.detail = (
                    "The provided verification key has expired or your email address is already verified."
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
        if certego_apps_settings.SLACK_TOKEN and certego_apps_settings.DEFAULT_SLACK_CHANNEL:
            userprofile = user.user_profile
            user_admin_link = f"{settings.WEB_CLIENT_URL}/admin/certego_saas_user/user/{user.pk}"
            userprofile_admin_link = (
                f"{settings.WEB_CLIENT_URL}/admin/authentication/userprofile/{userprofile.pk}"
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
                slack.log.error(f"Slack message failed for user(#{user.pk}) with error: {str(exc)}")


class LoginSerializer(AuthTokenSerializer):
    """
    Serializer for user login.

    Customizes error messages for inactive or unverified users.
    """

    def validate(self, attrs):
        """
        Validate the login credentials.

        Args:
            attrs (dict): The login credentials.

        Returns:
            dict: The validated data.

        Raises:
            ValidationError: If the credentials are invalid or the user is inactive.
        """
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
                    logger.info(f"User {user} is not active. Error message: {exc.detail}")
            # else
            raise exc


class TokenSerializer(rfs.ModelSerializer):
    """
    Serializer for API tokens.

    Attributes:
        key (str): The token key.
        created (datetime): The creation time of the token.
    """

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
        """
        Validate that a token has not already been issued to the user.

        Args:
            data (dict): The data to validate.

        Returns:
            dict: The validated data.

        Raises:
            ValidationError: If a token has already been issued to the user.
        """
        user = self.context["user"]
        if Token.objects.filter(user=user).exists():
            raise rfs.ValidationError("An API token was already issued to you.")
        data["user"] = user
        return data
