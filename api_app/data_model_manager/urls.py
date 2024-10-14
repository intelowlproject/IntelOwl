# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
from api_app.data_model_manager.views import FileDataModelView, IPDataModelView, DomainDataModelView
from api_app.ingestors_manager.views import IngestorConfigViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"domain", DomainDataModelView, basename="domain")
router.register(r"ip", IPDataModelView, basename="ip")
router.register(r"file", FileDataModelView, basename="file")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
