# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from authlib.integrations.base_client import OAuthError
from authlib.oauth2 import OAuth2Error
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import redirect
from django_user_agents.utils import get_user_agent
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from durin import views as durin_views
from durin.models import Client
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.reverse import reverse

from intel_owl.settings import AUTH_USER_MODEL

from .oauth import oauth

logger = logging.getLogger(__name__)

""" Auth API endpoints """

User: AUTH_USER_MODEL = get_user_model()


class LoginView(durin_views.LoginView):
    @staticmethod
    def get_client_obj(request) -> Client:
        user_agent = get_user_agent(request)
        client_name = str(user_agent)
        client, _ = Client.objects.get_or_create(name=client_name)
        return client

    def post(self, request, *args, **kwargs):
        response = super(LoginView, self).post(request, *args, **kwargs)
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
        return super(LogoutView, self).post(request, format=None)


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


def google_login(request):
    redirect_uri = request.build_absolute_uri(reverse("oauth_google_callback"))
    try:
        return oauth.google.authorize_redirect(request, redirect_uri)
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

    def get_post_response_data(self, request, token_obj) -> dict:
        data = {
            "token": token_obj.token,
        }
        return data
