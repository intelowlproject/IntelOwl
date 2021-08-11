# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path, include
from rest_framework import routers

from .views import ConnectorActionViewSet, ConnectorListAPI


# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"job/(?P<job_id>\d+)/connector/(?P<name>\w+)",
    ConnectorActionViewSet,
)

urlpatterns = [
    path("get_connector_configs", ConnectorListAPI.as_view()),
    # Viewsets
    path(r"", include(router.urls)),
]
