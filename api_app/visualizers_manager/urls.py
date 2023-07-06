# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
from api_app.visualizers_manager.views import (
    VisualizerActionViewSet,
    VisualizerConfigViewSet,
)

router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"jobs/(?P<job_id>\d+)/visualizer/(?P<report_id>\w+)",
    VisualizerActionViewSet,
    basename="visualizerreport",
)
router.register(r"visualizer", VisualizerConfigViewSet, basename="visualizer")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
