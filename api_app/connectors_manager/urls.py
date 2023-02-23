# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import ConnectorActionViewSet, ConnectorConfigAPI

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"jobs/(?P<job_id>\d+)/connector/(?P<name>\w+)",
    ConnectorActionViewSet,
)
router.register(r"connector", ConnectorConfigAPI, basename="connector")

urlpatterns = [
    path(r"", include(router.urls)),
]
