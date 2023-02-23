# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import (
    PlaybookConfigAPI,
    analyze_multiple_files,
    analyze_multiple_observables,
)

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"playbook", PlaybookConfigAPI, basename="playbook")

urlpatterns = [
    path(r"", include(router.urls)),
    path("playbook/analyze_multiple_files", analyze_multiple_files),
    path("playbook/analyze_multiple_observables", analyze_multiple_observables),
]
