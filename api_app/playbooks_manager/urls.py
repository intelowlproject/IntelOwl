# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import PlaybookConfigViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"playbook", PlaybookConfigViewSet, basename="playbook")

urlpatterns = [
    path(r"", include(router.urls)),
]
