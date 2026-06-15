# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import ChatAnalysisConfirmView, ChatHealthView, ChatSessionViewSet

router = DefaultRouter(trailing_slash=False)
router.register(r"sessions", ChatSessionViewSet, basename="chat-sessions")

urlpatterns = router.urls + [
    path("health", ChatHealthView.as_view(), name="chat-health"),
    path("analysis/confirm", ChatAnalysisConfirmView.as_view(), name="chat-analysis-confirm"),
]
