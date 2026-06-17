# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import ChatAnalysisConfirmView, ChatHealthView, ChatSessionViewSet

# These route suffixes are mirrored by the frontend in frontend/src/constants/apiURLs.js
# (CHATBOT_SESSIONS_URI / CHATBOT_HEALTH_URI / CHATBOT_ANALYSIS_CONFIRM_URI). They can't be imported
# across the JS/Python boundary, so a frontend coupling test
# (frontend/tests/components/chat/chatbotRouteCoupling.test.js) reads this file and breaks if a route
# is renamed here without updating the constant there. Keep both in sync.
router = DefaultRouter(trailing_slash=False)
router.register(r"sessions", ChatSessionViewSet, basename="chat-sessions")

urlpatterns = router.urls + [
    path("health", ChatHealthView.as_view(), name="chat-health"),
    path("analysis/confirm", ChatAnalysisConfirmView.as_view(), name="chat-analysis-confirm"),
]
