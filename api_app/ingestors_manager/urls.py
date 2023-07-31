# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
from api_app.ingestors_manager.views import IngestorConfigViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"ingestor", IngestorConfigViewSet, basename="ingestor")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
