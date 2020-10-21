import logging

from django.contrib.auth import login, logout
from durin import views as durin_views
from durin.models import Client

logger = logging.getLogger(__name__)


""" Auth API endpoints """


class LoginView(durin_views.LoginView):
    @staticmethod
    def get_client_obj(request):
        return Client.objects.get(name="web-browser")

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
