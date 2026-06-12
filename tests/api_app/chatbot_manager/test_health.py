# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

import requests
from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase

from api_app.chatbot_manager.health import (
    HEALTH_UNAVAILABLE_DETAIL,
    ChatHealth,
    chatbot_health,
)
from certego_saas.apps.user.models import User
from intel_owl.celery import get_queue_name

CHATBOT_QUEUE_NAME = get_queue_name(settings.CHATBOT_QUEUE)


def _celery_app(active_queues_return):
    """A fake celery_app whose control.inspect().active_queues() returns the given value."""
    app = MagicMock()
    app.control.inspect.return_value.active_queues.return_value = active_queues_return
    return app


class ChatbotHealthTestCase(APITestCase):
    def setUp(self):
        cache.clear()

    @patch("api_app.chatbot_manager.health.requests.get")
    @patch(
        "api_app.chatbot_manager.health.celery_app",
        _celery_app({"worker1": [{"name": CHATBOT_QUEUE_NAME}]}),
    )
    def test_available_when_worker_and_ollama_up(self, mock_get):
        mock_get.return_value = MagicMock(ok=True)
        health = chatbot_health()
        self.assertTrue(health.available)
        self.assertEqual(health.detail, "")

    @patch("api_app.chatbot_manager.health.requests.get")
    @patch(
        "api_app.chatbot_manager.health.celery_app",
        _celery_app(None),  # no worker replied within the timeout
    )
    def test_unavailable_when_no_chatbot_worker(self, mock_get):
        mock_get.return_value = MagicMock(ok=True)
        health = chatbot_health()
        self.assertFalse(health.available)
        self.assertEqual(health.detail, HEALTH_UNAVAILABLE_DETAIL)

    @patch(
        "api_app.chatbot_manager.health.requests.get",
        side_effect=requests.RequestException,
    )
    @patch(
        "api_app.chatbot_manager.health.celery_app",
        _celery_app({"worker1": [{"name": CHATBOT_QUEUE_NAME}]}),
    )
    def test_unavailable_when_ollama_unreachable(self, mock_get):
        health = chatbot_health()
        self.assertFalse(health.available)
        self.assertEqual(health.detail, HEALTH_UNAVAILABLE_DETAIL)

    @patch("api_app.chatbot_manager.health.requests.get")
    @patch("api_app.chatbot_manager.health.celery_app")
    def test_result_is_cached(self, mock_celery, mock_get):
        mock_celery.control.inspect.return_value.active_queues.return_value = {
            "worker1": [{"name": CHATBOT_QUEUE_NAME}]
        }
        mock_get.return_value = MagicMock(ok=True)
        chatbot_health()
        chatbot_health()
        # second call is served from the cache -> the probes ran exactly once
        mock_celery.control.inspect.assert_called_once()
        mock_get.assert_called_once()

    @patch("api_app.chatbot_manager.health.requests.get")
    @patch(
        "api_app.chatbot_manager.health.celery_app",
        _celery_app({"worker1": [{"name": "some-other-queue"}]}),
    )
    def test_unavailable_when_worker_serves_a_different_queue(self, mock_get):
        mock_get.return_value = MagicMock(ok=True)
        self.assertFalse(chatbot_health().available)


class ChatHealthViewTestCase(APITestCase):
    URL = "/api/chatbot/health"

    def setUp(self):
        cache.clear()
        self.user, _ = User.objects.get_or_create(username="chatbot_health_user")

    @patch(
        "api_app.chatbot_manager.views.chatbot_health",
        return_value=ChatHealth(available=False, detail="nope"),
    )
    def test_get_returns_serialized_health(self, _mock):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), {"available": False, "detail": "nope"})

    def test_requires_authentication(self):
        # IntelOwl's session/token auth returns 401 or 403 for an anonymous request.
        response = self.client.get(self.URL)
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )
