# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import List

import rest_email_auth.views
from allauth.socialaccount.helpers import perform_login

# social-login
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from authlib.integrations.base_client import OAuthError
from authlib.oauth2 import OAuth2Error
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.hashers import check_password
from django.shortcuts import redirect
from django_user_agents.utils import get_user_agent
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.utils import extend_schema as add_docs
from durin import views as durin_views
from durin.models import Client
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from certego_saas.ext.mixins import RecaptchaV2Mixin
from certego_saas.ext.throttling import POSTUserRateThrottle
from intel_owl.settings import AUTH_USER_MODEL

from .oauth import oauth
from .serializers import (  # LoginSerializer,
    EmailVerificationSerializer,
    RegistrationSerializer,
)

logger = logging.getLogger(__name__)

""" Auth API endpoints """

User: AUTH_USER_MODEL = get_user_model()


class PasswordResetRequestView(
    rest_email_auth.views.PasswordResetRequestView, RecaptchaV2Mixin
):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class PasswordResetView(rest_email_auth.views.PasswordResetView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class EmailVerificationView(rest_email_auth.views.EmailVerificationView):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = EmailVerificationSerializer


class RegistrationView(rest_email_auth.views.RegistrationView, RecaptchaV2Mixin):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]
    serializer_class = RegistrationSerializer

    def get_serializer_class(self):  # skipcq: PYL-R0201
        return RegistrationSerializer


class ResendVerificationView(
    rest_email_auth.views.ResendVerificationView, RecaptchaV2Mixin
):
    authentication_classes: List = []
    permission_classes: List = []
    throttle_classes: List = [POSTUserRateThrottle]


class LoginView(durin_views.LoginView):
    @staticmethod
    def get_client_obj(request) -> Client:
        user_agent = get_user_agent(request)
        client_name = str(user_agent)
        client, _ = Client.objects.get_or_create(name=client_name)
        return client

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        uname = request.user.username
        logger.info(f"LoginView: received request from '{uname}'.")
        if request.user.is_superuser:
            try:
                # pass admin user's session
                login(request, request.user)
                logger.info(f"administrator:'{uname}' was logged in.")
            except Exception:
                logger.exception(f"administrator:'{uname}' login failed.")
        return response


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    @staticmethod
    def post(request: Request) -> Response:
        # Get the old password and new password from the request data
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        # Check if the old password matches the user's current password
        user = request.user
        uname = user.username
        if not check_password(old_password, user.password):
            logger.info(f"'{uname}' has inputted invalid old password.")
            # Return an error response if the old password doesn't match
            return Response(
                {"error": "Invalid old password"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Set the new password for the user
        user.set_password(new_password)
        user.save()

        # Return a success response
        return Response({"message": "Password changed successfully"})


class LogoutView(durin_views.LogoutView):
    def post(self, request, *args, **kwargs):
        uname = request.user.username
        logger.info(f"perform_logout received request from '{uname}''.")
        if request.user.is_superuser:
            try:
                logout(request)
                logger.info(f"administrator: '{uname}' was logged out.")
            except Exception:
                logger.exception(f"administrator: '{uname}' session logout failed.")
        return super().post(request, format=None)


APIAccessTokenView = durin_views.APIAccessTokenView
TokenSessionsViewSet = durin_views.TokenSessionsViewSet


class DurinAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "durin.auth.CachedTokenAuthentication"
    name = "durinAuth"

    @staticmethod
    def get_security_definition(auto_schema):
        return {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Token-based authentication with required prefix: Token",
        }


@add_docs(
    description="""This endpoint redirects to Google OAuth login.""",
)
@api_view(["GET"])
@permission_classes([AllowAny])
def google_login(request: Request):
    """
    Redirect to Google OAuth login
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
    @staticmethod
    def validate_and_return_user(request):
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
            return User.objects.create_user(
                email=user_email, username=user_name, password=None
            )

    def get(self, *args, **kwargs):
        return self.post(*args, **kwargs)

    def post(self, *args, **kwargs):
        response = super().post(*args, **kwargs)
        token = response.data["token"]
        # Uncomment this for local testing
        # return redirect(f"http://localhost:3001/login?token={token}")
        return redirect(self.request.build_absolute_uri(f"/login?token={token}"))

    @staticmethod
    def get_post_response_data(request, token_obj) -> dict:
        data = {
            "token": token_obj.token,
        }
        return data


@api_view(["get"])
@permission_classes([AllowAny])
def check_registration_setup(request):
    logger.info(f"Requested checking registration setup from {request.user}.")
    errors = {}

    # email setup
    if not settings.DEFAULT_FROM_EMAIL:
        errors["DEFAULT_FROM_EMAIL"] = "required"
    if not settings.DEFAULT_EMAIL:
        errors["DEFAULT_EMAIL"] = "required"

    # if you are in production environment
    if settings.STAGE_PRODUCTION:
        # SES backend
        if settings.AWS_SES:
            if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
                errors["AWS SES backend"] = "configuration required"
        else:
            # SMTP backend
            required_variables = [
                settings.EMAIL_HOST,
                settings.EMAIL_HOST_USER,
                settings.EMAIL_HOST_PASSWORD,
                settings.EMAIL_PORT,
            ]
            for variable in required_variables:
                if not variable:
                    errors["SMTP backend"] = "configuration required"

        # recaptcha key
        if settings.DRF_RECAPTCHA_SECRET_KEY == "fake":
            errors["RECAPTCHA_SECRET_KEY"] = "required"

    logger.info(f"Registration setup errors: {errors}")
    if errors:
        return Response(status=status.HTTP_501_NOT_IMPLEMENTED)
    return Response(status=status.HTTP_200_OK)


class GitHubLoginCallbackView(LoginView):
    def get(self, request):
        code = request.GET.get("code")

        if code:
            github_adapter = GitHubOAuth2Adapter()
            client = OAuth2Client(request)
            access_token = github_adapter.access_token(request, client, code)

            # Get user data
            github_account = github_adapter.get_user_info(access_token)
            user_email = github_account.get("email")
            user_name = github_account.get("name")

            # Check if user exists
            try:
                user = User.objects.get(email=user_email)
            except User.DoesNotExist:
                # Create new user
                user = User.objects.create_user(email=user_email, username=user_name)

            # Login user
            account = SocialAccount(provider="github", user=user)
            account.extra_data = {"access_token": access_token.token}
            account.save()
            token = SocialToken(account=account, token=access_token.token)
            token.token_secret = access_token.token_secret
            token.app = SocialApp.objects.get(provider="github")
            token.save()

            perform_login(
                request, user, "allauth.account.auth_backends.AuthenticationBackend"
            )

            return redirect(self.request.build_absolute_uri(f"/login?token={token}"))

        return redirect("http://localhost/login/")
