# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import PlaybookActionViewSet, PlaybookListAPI

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter(trailing_slash=False)
router.register(
    r"jobs/(?P<job_id>\d+)/playbook/(?P<name>\w+)",
    PlaybookActionViewSet,
)

urlpatterns = [
    path("get_playbook_configs", PlaybookListAPI.as_view()),
    # Viewsets
    path(r"", include(router.urls)),

]

