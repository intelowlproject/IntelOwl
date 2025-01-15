# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from api_app.engines_manager.views import EngineViewSet

# Routers provide an easy way of automatically determining the URL conf.


router = routers.DefaultRouter(trailing_slash=False)
router.register(r"engine", EngineViewSet, basename="engine")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
