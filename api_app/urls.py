# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .api import (
    ask_analysis_availability,
    send_analysis_request,
    download_sample,
    TagViewSet,
    JobViewSet,
)

from .auth import LoginView, LogoutView


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"tags", TagViewSet)
router.register(r"jobs", JobViewSet)

# These come after /api/..
urlpatterns = [
    # Auth APIs
    path("auth/login", LoginView.as_view(), name="auth_login"),
    path("auth/logout", LogoutView.as_view(), name="auth_logout"),
    # Main APIs
    path("ask_analysis_availability", ask_analysis_availability),
    path("send_analysis_request", send_analysis_request),
    path("download_sample", download_sample),
    path(r"", include("api_app.analyzers_manager.urls")),
    # Viewsets
    path(r"", include(router.urls)),
]
