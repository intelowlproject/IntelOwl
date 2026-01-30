# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    CommentViewSet,
    ElasticSearchView,
    JobViewSet,
    PluginConfigViewSet,
    TagViewSet,
    analyze_file,
    analyze_multiple_files,
    analyze_multiple_observables,
    analyze_observable,
    ask_analysis_availability,
    ask_multi_analysis_availability,
    plugin_state_viewer,
)

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"tags", TagViewSet, basename="tags")
router.register(r"jobs", JobViewSet, basename="jobs")
router.register(r"comments", CommentViewSet, basename="comments")
router.register(r"plugin-config", PluginConfigViewSet, basename="plugin-config")

# These come after /api/..
urlpatterns = [
    # standalone endpoints
    path("ask_analysis_availability", ask_analysis_availability),
    path("ask_multi_analysis_availability", ask_multi_analysis_availability),
    path("analyze_file", analyze_file),
    path("analyze_multiple_files", analyze_multiple_files, name="analyze_multiple_files"),
    path("analyze_observable", analyze_observable),
    path(
        "analyze_multiple_observables",
        analyze_multiple_observables,
        name="analyze_multiple_observables",
    ),
    path(
        "plugin_report_queries",
        ElasticSearchView.as_view(),
        name="plugin-report-queries",
    ),
    # router viewsets
    path("", include(router.urls)),
    # Plugins
    path("", include("api_app.analyzers_manager.urls")),
    path("", include("api_app.connectors_manager.urls")),
    path("", include("api_app.visualizers_manager.urls")),
    path("", include("api_app.ingestors_manager.urls")),
    path("", include("api_app.pivots_manager.urls")),
    path("", include("api_app.playbooks_manager.urls")),
    path("", include("api_app.investigations_manager.urls")),
    path("data_model/", include("api_app.data_model_manager.urls")),
    path("user_event/", include("api_app.user_events_manager.urls")),
    path("", include("api_app.analyzables_manager.urls")),
    # auth
    path("auth/", include("authentication.urls")),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # notifications sub-app
    path("", include("certego_saas.apps.notifications.urls")),
    # organization sub-app
    path("me/", include("certego_saas.apps.organization.urls")),
    # this is for retro-compatibility
    path("plugin-disable/", plugin_state_viewer, name="plugin_state_viewer"),
]
