# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework.routers import DefaultRouter

from .views import ChatSessionViewSet

router = DefaultRouter(trailing_slash=False)
router.register(r"sessions", ChatSessionViewSet, basename="chat-sessions")

urlpatterns = router.urls
