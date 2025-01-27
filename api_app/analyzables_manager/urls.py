# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from api_app.analyzables_manager.views import AnalyzableViewSet

# Routers provide an easy way of automatically determining the URL conf.


router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analyzable", AnalyzableViewSet, basename="analyzable")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
