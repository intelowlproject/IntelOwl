# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .analyzers_manager import views as analyzers_manager_views
from .api import (
    JobViewSet,
    TagViewSet,
    analyze_file,
    analyze_observable,
    ask_analysis_availability,
)
from .auth import APIAccessTokenView, LoginView, LogoutView, TokenSessionsViewSet
from .connectors_manager import views as connectors_manager_views

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"auth/sessions", TokenSessionsViewSet, basename="auth_tokensessions")
router.register(r"tags", TagViewSet, basename="tags")
router.register(r"jobs", JobViewSet, basename="jobs")
router.register(
    r"jobs/(?P<job_id>\d+)/analyzer/(?P<name>\w+)",
    analyzers_manager_views.AnalyzerActionViewSet,
)
router.register(
    r"jobs/(?P<job_id>\d+)/connector/(?P<name>\w+)",
    connectors_manager_views.ConnectorActionViewSet,
)


# These come after /api/..
urlpatterns = [
    # auth
    path("auth/login", LoginView.as_view(), name="auth_login"),
    path("auth/logout", LogoutView.as_view(), name="auth_logout"),
    path("auth/apiaccess", APIAccessTokenView.as_view(), name="auth_apiaccess"),
    # standalone endpoints
    path("ask_analysis_availability", ask_analysis_availability),
    path("analyze_file", analyze_file),
    path("analyze_observable", analyze_observable),
    # Plugins (analyzers_manager, connectors_manager)
    path("get_analyzer_configs", analyzers_manager_views.AnalyzerListAPI.as_view()),
    path("get_connector_configs", connectors_manager_views.ConnectorListAPI.as_view()),
    path(
        "analyzer/<str:name>/healthcheck",
        analyzers_manager_views.AnalyzerHealthCheckAPI.as_view(),
    ),
    path(
        "connector/<str:name>/healthcheck",
        connectors_manager_views.ConnectorHealthCheckAPI.as_view(),
    ),
    # router viewsets
    path("", include(router.urls)),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # notifications sub-app
    path("", include("certego_saas.apps.notifications.urls")),
    # organization sub-app
    path("me/", include("certego_saas.apps.organization.urls")),
]
