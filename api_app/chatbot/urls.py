# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import ChatSessionViewSet, send_message

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"chatbot/sessions", ChatSessionViewSet, basename="chatbot-sessions")

urlpatterns = [
    path("", include(router.urls)),
    path(
        "chatbot/sessions/<uuid:session_pk>/messages",
        send_message,
        name="chatbot-send-message",
    ),
]
