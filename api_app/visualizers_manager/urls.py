# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
from api_app.visualizers_manager.views import VisualizerListAPI

router = routers.DefaultRouter(trailing_slash=False)

urlpatterns = [
    path(
        "get_visualizer_configs",
        VisualizerListAPI.as_view(),
        name="get_visualizer_configs",
    ),
    # Viewsets
    path(r"", include(router.urls)),
]
