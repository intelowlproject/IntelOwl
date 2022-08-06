# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    APIAccessTokenView,
    GoogleLoginCallbackView,
    LoginView,
    LogoutView,
    TokenSessionsViewSet,
    google_login,
)

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"sessions", TokenSessionsViewSet, basename="auth_tokensessions")

urlpatterns = [
    # auth
    path("login", LoginView.as_view(), name="auth_login"),
    path("logout", LogoutView.as_view(), name="auth_logout"),
    path("apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
    path("google", google_login, name="oauth_google"),
    path(
        "google-callback",
        GoogleLoginCallbackView.as_view(),
        name="oauth_google_callback",
    ),
    path("", include(router.urls)),
]
