# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

# Routers provide an easy way of automatically determining the URL conf.
from api_app.pivot_manager.views import PivotConfigViewSet, PivotViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"pivotconfig", PivotConfigViewSet, basename="pivotconfig")
router.register(r"pivot", PivotViewSet, basename="pivot")

urlpatterns = [
    path(r"", include(router.urls)),
]
