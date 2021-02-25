from django.urls import include, path
from rest_framework import routers
from durin.auth import CachedTokenAuthentication
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from .api import (
    ask_analysis_availability,
    send_analysis_request,
    ask_analysis_result,
    get_analyzer_configs,
    download_sample,
    TagViewSet,
    JobViewSet,
)

from .auth import LoginView, LogoutView


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"tags", TagViewSet)
router.register(r"jobs", JobViewSet)

schema_view = get_schema_view(
    openapi.Info(
        title="IntelOwl API",
        default_version="v1",
        license=openapi.License(name="AGPL-3.0 License "),
    ),
    public=True,
    authentication_classes=(CachedTokenAuthentication,),
)

# These come after /api/..
urlpatterns = [
    # Auth APIs
    path("auth/login", LoginView.as_view(), name="auth_login"),
    path("auth/logout", LogoutView.as_view(), name="auth_logout"),
    # Main APIs
    path("ask_analysis_availability", ask_analysis_availability),
    path("send_analysis_request", send_analysis_request),
    path("ask_analysis_result", ask_analysis_result),
    path("get_analyzer_configs", get_analyzer_configs),
    path("download_sample", download_sample),
    # Viewsets
    path(r"", include(router.urls)),
    # API Docs from swagger
    path(
        "docs/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]
