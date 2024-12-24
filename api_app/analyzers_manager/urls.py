# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    AnalyzerActionViewSet,
    AnalyzerConfigViewSet,
    AnalyzerPluginConfigViewSet,
)

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"jobs/(?P<job_id>\d+)/analyzer/(?P<report_id>\w+)",
    AnalyzerActionViewSet,
    basename="analyzerreport",
)
router.register(r"analyzer", AnalyzerConfigViewSet, basename="analyzer")
router.register(
    r"analyzer/(?P<name>\w+)",
    AnalyzerPluginConfigViewSet,
    basename="plugin-config-analyzer",
)


urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
