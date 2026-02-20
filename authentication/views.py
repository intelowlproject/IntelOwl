# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List

import rest_email_auth.views
from authlib.integrations.base_client import OAuthError
from authlib.oauth2 import OAuth2Error
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.hashers import check_password
from django.shortcuts import redirect
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from certego_saas.ext.throttling import POSTUserRateThrottle
from intel_owl.settings import AUTH_USER_MODEL

from .oauth import oauth
from .serializers import (
    EmailVerificationSerializer,
    LoginSerializer,
    RegistrationSerializer,
    TokenSerializer,
)

logger = logging.getLogger(__name__)

""" Auth API endpoints """

User: AUTH_USER_MODEL = get_user_model()


class PasswordResetRequestView(rest_email_auth.views.PasswordResetRequestView):
    """
    Handles requests for password reset.

    Args:
        rest_email_auth.views.PasswordResetRequestView:
        The parent view class for password reset requests.
    """

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class PasswordResetView(rest_email_auth.views.PasswordResetView):
    """
    Handles password reset.

    Args:
        rest_email_auth.views.PasswordResetView:
        The parent view class for password reset.
    """

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class EmailVerificationView(rest_email_auth.views.EmailVerificationView):
    """
    Handles email verification.

    Args:
        rest_email_auth.views.EmailVerificationView:
        The parent view class for email verification.
    """

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = EmailVerificationSerializer


class RegistrationView(rest_email_auth.views.RegistrationView):
    """
    Handles user registration.

    Args:
        rest_email_auth.views.RegistrationView:
        The parent view class for user registration.
    """

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = RegistrationSerializer

    def get_serializer_class(self):  # skipcq: PYL-R0201
        """
        Returns the serializer class for registration.

        Returns:
            RegistrationSerializer: The serializer class for user registration.
        """
        return RegistrationSerializer


class ResendVerificationView(rest_email_auth.views.ResendVerificationView):
    """
    Handles re-sending email verification.

    Args:
        rest_email_auth.views.ResendVerificationView:
        The parent view class for resending email verification.
    """

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class LoginView(APIView):
    """
    Handles user login."""

    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]

    @staticmethod
    def validate_and_return_user(request):
        """
        Validates user credentials and returns the user object.

        Args:
            request (Request): The request object containing user credentials.

        Returns:
            Any: The authenticated user object.
        """
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return serializer.validated_data["user"]

    def post(self, request, *args, **kwargs):
        """
        Handles POST request for user login.

        Args:
            request (Request): The request object containing user credentials.

        Returns:
            Response: The response object.
        """
        user = self.validate_and_return_user(request=request)
        logger.info(f"perform_login received request from '{user.username}''.")
        login(request, user)
        return Response()


class ChangePasswordView(APIView):
    """
    Handles changing user password.
    """

    permission_classes = [IsAuthenticated]

    @staticmethod
    def post(request: Request) -> Response:
        # Get the old password and new password from the request data
        """
        Handles POST request for changing user password.

        Args:
            request (Request): The request object containing old and new passwords.

        Returns:
            Response: The response object.
        """
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        # Check if the old password matches the user's current password
        user = request.user
        uname = user.username
        if not check_password(old_password, user.password):
            logger.info(f"'{uname}' has inputted invalid old password.")
            # Return an error response if the old password doesn't match
            return Response({"error": "Invalid old password"}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password for the user
        user.set_password(new_password)
        user.save()

        # Return a success response
        return Response({"message": "Password changed successfully"})


class LogoutView(APIView):
    """
    Handles user logout.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):  # skipcq: PYL-R0201
        """
        Handles POST request for user logout.

        Args:
            request (Request): The request object.

        Returns:
            Response: The response object.
        """
        user = request.user
        logger.info(f"perform_logout received request from '{user.username}''.")
        logout(request)
        return Response()


@api_view(["GET"])
@permission_classes([AllowAny])
def google_login(request: Request):
    """
    Redirect to Google OAuth login

    Args:
        request (Request): The request object.

    Returns:
        Response: The response object.
    """
    redirect_uri = request.build_absolute_uri(reverse("oauth_google_callback"))
    try:
        response = oauth.google.authorize_redirect(request, redirect_uri)
        if request.query_params.get("no_redirect") == "true":
            return Response(status=status.HTTP_200_OK)
        return response
    except AttributeError as error:
        if "No such client: " in str(error):
            raise AuthenticationFailed("Google OAuth is not configured.")
        raise error


class GoogleLoginCallbackView(LoginView):
    """
    Handles Google OAuth login callback.
    """

    @staticmethod
    def validate_and_return_user(request):
        """
        Validates Google OAuth token and returns the user object.

        Args:
            request (Request): The request object.

        Returns:
            Any: The authenticated user object.
        """
        try:
            token = oauth.google.authorize_access_token(request)
        except (
            OAuthError,
            OAuth2Error,
        ):
            # Not giving out the actual error as we risk exposing the client secret
            raise AuthenticationFailed("OAuth authentication error.")
        user = token.get("userinfo")
        user_email = user.get("email")
        user_name = user.get("name")
        try:
            return User.objects.get(email=user_email)
        except User.DoesNotExist:
            logging.info("[Google Oauth] User does not exist. Creating new user.")
            return User.objects.create_user(email=user_email, username=user_name, password=None)

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        user = self.validate_and_return_user(request=request)
        logger.info(f"perform_login received request from '{user.username}''.")
        login(request, user)
        # Uncomment this for local testing
        # return redirect("http://localhost/login")
        return redirect(self.request.build_absolute_uri("/login"))


@api_view(["get"])
@permission_classes([AllowAny])
def checkConfiguration(request):
    """
    Checks the configuration settings.

    Args:
        request (Request): The request object.

    Returns:
        Response: The response object.
    """
    logger.info(f"Requested checking configuration from {request.user}.")
    page = request.query_params.get("page")
    register_uri = reverse("auth_register")
    errors = {}

    if page == register_uri.split("/")[-1]:
        # email setup
        if not settings.DEFAULT_FROM_EMAIL:
            errors["DEFAULT_FROM_EMAIL"] = "required"
        if not settings.DEFAULT_EMAIL:
            errors["DEFAULT_EMAIL"] = "required"

        # SES backend
        if settings.AWS_SES:
            if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
                errors["AWS SES backend"] = "configuration required"
        else:
            # SMTP backend
            if not all(
                [
                    settings.EMAIL_HOST,
                    settings.EMAIL_HOST_USER,
                    settings.EMAIL_HOST_PASSWORD,
                    settings.EMAIL_PORT,
                ]
            ):
                errors["SMTP backend"] = "configuration required"

    logger.info(f"Configuration errors: {errors}")
    return Response(status=status.HTTP_200_OK, data={"errors": errors} if errors else {})


class APIAccessTokenView(APIView):
    """
    - ``GET`` -> get token-client pair info
    - ``POST`` -> create and get token-client pair info
    - ``DELETE`` -> delete existing API access token
    Handles API access token operations.
    """

    permission_classes = [IsAuthenticated]

    def get_object(self):
        try:
            instance = Token.objects.get(user__pk=self.request.user.pk)
        except Token.DoesNotExist:
            raise NotFound()

        return instance

    def get(self, request, *args, **kwargs):
        """
        Handles GET request for retrieving API access token.

        Args:
            request (Request): The request object.

        Returns:
            Response: The response object.
        """
        instance = self.get_object()
        logger.info(f" user {request.user} request the API token")
        serializer = TokenSerializer(instance)
        return Response(serializer.data)

    def post(self, request):  # skipcq: PYL-R0201
        """
        Handles POST request for creating API access token.

        Args:
            request (Request): The request object.

        Returns:
            Response: The response object.
        """
        username = request.user.username
        logger.info(f"user {username} send a request to create the API token")
        serializer = TokenSerializer(data={}, context={"user": request.user})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request):
        """
        Handles DELETE request for deleting API access token.

        Args:
            request (Request): The request object.

        Returns:
            Response: The response object.
        """
        logger.info(f"user {request.user} send a request to delete the API token")
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
