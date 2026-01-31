# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from api_app.user_events_manager.views import (
    UserAnalyzableEventViewSet,
    UserDomainWildCardEventViewSet,
    UserIPWildCardEventViewSet,
)

# Routers provide an easy way of automatically determining the URL conf.


router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analyzable", UserAnalyzableEventViewSet, basename="user_analyzable_event")
router.register(
    r"domain_wildcard",
    UserDomainWildCardEventViewSet,
    basename="user_domain_analyzable_event",
)
router.register(r"ip_wildcard", UserIPWildCardEventViewSet, basename="user_ip_analyzable_event")

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls)),
]
