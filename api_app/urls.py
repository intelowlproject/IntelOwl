from django.urls import include, path
from rest_framework import routers

from .api import (
    ask_analysis_availability,
    send_analysis_request,
    ask_analysis_result,
    get_analyzer_configs,
    download_sample,
    TagViewSet,
    JobViewSet,
)

from .auth import obtain_user_token, perform_logout, CustomTokenRefreshView


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"tags", TagViewSet)
router.register(r"jobs", JobViewSet)

# These come after /api/..
urlpatterns = [
    # Auth APIs
    path("auth/login", obtain_user_token),
    path("auth/logout", perform_logout),
    path("auth/refresh-token", CustomTokenRefreshView.as_view(), name="refresh_token"),
    # Main APIs
    path("ask_analysis_availability", ask_analysis_availability),
    path("send_analysis_request", send_analysis_request),
    path("ask_analysis_result", ask_analysis_result),
    path("get_analyzer_configs", get_analyzer_configs),
    path("download_sample", download_sample),
    # Viewsets
    path(r"", include(router.urls)),
]
