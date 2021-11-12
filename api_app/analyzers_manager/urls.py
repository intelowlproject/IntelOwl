# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from . import views

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"job/(?P<job_id>\d+)/analyzer/(?P<name>\w+)",
    views.AnalyzerActionViewSet,
)

urlpatterns = [
    path("get_analyzer_configs", views.AnalyzerListAPI.as_view()),
    path("analyzer/<str:name>/healthcheck", views.AnalyzerHealthCheckAPI.as_view()),
    # Viewsets
    path(r"", include(router.urls)),
]
