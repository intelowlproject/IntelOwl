# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    APIAccessTokenView,
    ChangePasswordView,
    EmailVerificationView,
    GoogleLoginCallbackView,
    LoginView,
    LogoutView,
    PasswordResetRequestView,
    PasswordResetView,
    RegistrationView,
    ResendVerificationView,
    checkConfiguration,
    google_login,
)

router = routers.DefaultRouter(trailing_slash=False)

urlpatterns = [
    # django-rest-email-auth
    path(
        "verify-email",
        EmailVerificationView.as_view(),
        name="auth_verify-email",
    ),
    path(
        "resend-verification",
        ResendVerificationView.as_view(),
        name="auth_resend-verification",
    ),
    path(
        "register",
        RegistrationView.as_view(),
        name="auth_register",
    ),
    path(
        "request-password-reset",
        PasswordResetRequestView.as_view(),
        name="auth_request-password-reset",
    ),
    path("reset-password", PasswordResetView.as_view(), name="auth_reset-password"),
    # auth
    path("login", LoginView.as_view(), name="auth_login"),
    path("logout", LogoutView.as_view(), name="auth_logout"),
    path("changepassword", ChangePasswordView.as_view(), name="auth_changepassword"),
    path("apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
    path("google", google_login, name="oauth_google"),
    path(
        "google-callback",
        GoogleLoginCallbackView.as_view(),
        name="oauth_google_callback",
    ),
    path("configuration", checkConfiguration, name="auth_configuration"),
    path("", include(router.urls)),
]
