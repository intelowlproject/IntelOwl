# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path, include
from rest_framework import routers

from .views import AnalyzerActionViewSet, AnalyzerListAPI


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"job/(?P<job_id>\d+)/analyzer/(?P<name>\w+)",
    AnalyzerActionViewSet,
    basename="analyzer",
)

urlpatterns = [
    path("get_analyzer_configs", AnalyzerListAPI.as_view()),
    # Viewsets
    path(r"", include(router.urls)),
]
