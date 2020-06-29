import logging

from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)

from api_app import serializers


logger = logging.getLogger(__name__)


""" Auth API endpoints """


@api_view(["POST"])
@authentication_classes([])
@permission_classes([])
def obtain_user_token(request):
    """
    REST endpoint to obtain user auth token via authentication

    :param username: string
        username of registered user
    :param password: string
        password of registered user

    :return 202:
        if accepted
    :return 404:
        if failed
    """
    try:
        username = request.data["username"]
        logger.info(f"obtain_user_token received request for '{username}'.")
        password = request.data["password"]
        auth_user = authenticate(username=username, password=password)
        if auth_user:
            if auth_user.is_superuser:
                try:
                    logger.info(f"headers: {request.headers}")
                    # pass admin user's session
                    login(request, auth_user)
                    logger.info(f"administrator:'{username}' was logged in.")
                except Exception:
                    logger.exception(f"administrator:'{username}' login failed.")

            refresh = RefreshToken.for_user(auth_user)
            logger.debug(f"obtain_user_token: token created for '{username}'.")
            # adding custom 'username' claim
            refresh["username"] = auth_user.username
            return Response(
                {"refresh": str(refresh), "access": str(refresh.access_token)},
                status=status.HTTP_202_ACCEPTED,
            )
        raise APIException(
            "No such user exists or Incorrect credentials",
            code=status.HTTP_400_BAD_REQUEST,
        )

    except APIException as e:
        logger.exception(f"obtain_user_token exception: {e}")
        return Response({"error": str(e)}, status=e.status_code)


class CustomTokenRefreshView(TokenRefreshView):
    """
    REST endpoint that returns new `token` object consisting of
    `access` and `refresh` fields
    given a valid `refresh` token.

    :methods_allowed:
        POST

    :param request.data:
        JSON[refresh]

    :return 201:
        if accepted and created new token
    :return 400:
        if failed
    """

    serializer_class = serializers.TokenRefreshPatchedSerializer


@api_view(["POST"])
def perform_logout(request):
    """
    REST endpoint to delete/invalidate user auth token and logout user.
    Requires authentication.

    :param refresh: string
        user's current refresh token that will be blacklisted

    :return 200:
        if ok
    :return 400:
        if failed
    """
    try:
        user = request.user
        logger.info(f"perform_logout received request from {user.username}.")
        recvd_refresh_token = request.data["refresh"]
        refresh = RefreshToken(recvd_refresh_token)
        if user.is_superuser:
            try:
                logout(request)
                logger.info(f"administrator:'{user.username}' was logged out.")
            except Exception:
                logger.exception(
                    f"administrator:'{user.username}' session logout failed."
                )
        try:
            # Attempt to blacklist the given refresh token
            refresh.blacklist()
            logger.info("perform_logout: current token was blacklisted.")
        except AttributeError:
            # If blacklist app not installed, `blacklist` method will
            # not be present
            logger.exception("perform_logout: token_blacklist app is not installed.")

        return Response(
            {"status": "You've been logged out."}, status=status.HTTP_200_OK
        )
    except Exception as e:
        str_err = str(e)
        logger.exception(f"perform_logout exception: {str_err}")
        return Response({"error": str_err}, status=status.HTTP_400_BAD_REQUEST)
