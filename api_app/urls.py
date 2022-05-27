# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    JobViewSet,
    TagViewSet,
    analyze_file,
    analyze_multiple_observables,
    analyze_observable,
    ask_analysis_availability,
)

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"tags", TagViewSet, basename="tags")
router.register(r"jobs", JobViewSet, basename="jobs")

# These come after /api/..
urlpatterns = [
    # standalone endpoints
    path("ask_analysis_availability", ask_analysis_availability),
    path("analyze_file", analyze_file),
    path("analyze_observable", analyze_observable),
    path("analyze_multiple_observables", analyze_multiple_observables),
    # router viewsets
    path("", include(router.urls)),
    # Plugins (analyzers_manager, connectors_manager)
    path("", include("api_app.analyzers_manager.urls")),
    path("", include("api_app.connectors_manager.urls")),
    # auth
    path("auth/", include("api_app.authentication.urls")),
    # certego_saas:
    # default apps (user),
    path("", include("certego_saas.urls")),
    # notifications sub-app
    path("", include("certego_saas.apps.notifications.urls")),
    # organization sub-app
    path("me/", include("certego_saas.apps.organization.urls")),
]
