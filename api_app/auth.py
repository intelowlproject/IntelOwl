import logging

from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
)


logger = logging.getLogger(__name__)


""" Auth API endpoints """


@api_view(["POST"])
@authentication_classes([])
@permission_classes([])
def perform_login(request):
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

            token, _created = Token.objects.get_or_create(user=auth_user)
            logger.debug(f"obtain_user_token: token created for '{username}'.")
            # adding custom 'username' claim
            resp = {
                "username": auth_user.username,
                "token": str(token.key),
            }
            return Response(
                resp,
                status=status.HTTP_202_ACCEPTED,
            )
        raise APIException(
            "No such user exists or Incorrect credentials",
            code=status.HTTP_400_BAD_REQUEST,
        )

    except APIException as e:
        logger.exception(f"obtain_user_token exception: {e}")
        return Response({"error": str(e)}, status=e.status_code)


@api_view(["POST"])
def perform_logout(request):
    """
    REST endpoint to delete auth token and logout user.
    Requires authentication.

    :return 200:
        if ok
    :return 400:
        if failed
    """
    try:
        uname = request.user.username
        logger.info(f"perform_logout received request from '{uname}''.")
        token = request.auth
        if token:
            token.delete()
            logger.info(f"perform_logout: deleted current token for '{uname}'.")
        if request.user.is_superuser:
            try:
                logout(request)
                logger.info(f"administrator: '{uname}' was logged out.")
            except Exception:
                logger.exception(f"administrator: '{uname}' session logout failed.")
        return Response(
            {"status": "You've been logged out."}, status=status.HTTP_200_OK
        )
    except Exception as e:
        str_err = str(e)
        logger.exception(f"perform_logout exception: {str_err}")
        return Response({"error": str_err}, status=status.HTTP_400_BAD_REQUEST)
