# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import AsyncMock, MagicMock, patch

from asgiref.sync import async_to_sync
from django.contrib.auth.models import AnonymousUser
from django.test import SimpleTestCase, TestCase

from api_app.chatbot_manager import events
from api_app.chatbot_manager.consumers import ChatConsumer
from api_app.chatbot_manager.models import ChatSession
from certego_saas.apps.user.models import User
from intel_owl.middleware import WSAuthMiddleware

CHANNEL_NAME = "test.channel"


def _make_consumer(user):
    """A ChatConsumer wired for direct (synchronous) method calls.

    The consumer's sync methods (connect/receive_json/disconnect) are exercised directly with an
    injected scope and a mocked channel layer. This deliberately avoids WebsocketCommunicator: a
    sync consumer keeps a channel-layer receive listener bound to its event loop, and tearing
    that down across the fresh per-test loops that async_to_sync creates hangs. The group_add /
    group_discard / accept / send_json side effects are mocked, so each behaviour is asserted
    deterministically.
    """
    consumer = ChatConsumer()
    consumer.scope = {"user": user, "query_string": b"", "url_route": {"kwargs": {}}}
    consumer.channel_name = CHANNEL_NAME
    consumer.channel_layer = MagicMock()
    consumer.channel_layer.group_add = AsyncMock()
    consumer.channel_layer.group_discard = AsyncMock()
    consumer.accept = MagicMock()
    consumer.send_json = MagicMock()
    consumer.context_url = ""  # connect() sets this from the scope; receive_json tests skip connect()
    return consumer


class ChatConsumerTestCase(TestCase):
    """ChatConsumer auth-scoped group join, session resolution, and task enqueue."""

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="chat_ws_user")

    def test_connect_joins_only_its_per_user_group(self):
        consumer = _make_consumer(self.user)
        consumer.connect()

        consumer.accept.assert_called_once()
        expected_group = events.chat_group_for_user(self.user.id)
        # the group is keyed on the authenticated user id, so a client only gets its own stream
        self.assertEqual(consumer.group_name, expected_group)
        consumer.channel_layer.group_add.assert_called_once_with(expected_group, CHANNEL_NAME)

    def test_disconnect_leaves_the_group(self):
        consumer = _make_consumer(self.user)
        consumer.connect()
        consumer.disconnect(1000)

        consumer.channel_layer.group_discard.assert_called_once_with(
            events.chat_group_for_user(self.user.id), CHANNEL_NAME
        )

    @patch("api_app.chatbot_manager.consumers.process_chat_message")
    def test_message_creates_session_acks_and_enqueues(self, mock_task):
        consumer = _make_consumer(self.user)
        consumer.receive_json({"message": "hello"})

        session = ChatSession.objects.get(user=self.user)
        consumer.send_json.assert_called_once_with(events.AckEvent(session.id).to_client())
        mock_task.delay.assert_called_once_with(session.id, "hello", self.user.id, "")

    @patch("api_app.chatbot_manager.consumers.process_chat_message")
    def test_existing_owned_session_is_reused(self, mock_task):
        session = ChatSession.objects.create(user=self.user)
        consumer = _make_consumer(self.user)
        consumer.receive_json({"message": "again", "session_id": session.id})

        # no new session is created when a valid owned id is supplied
        self.assertEqual(ChatSession.objects.filter(user=self.user).count(), 1)
        consumer.send_json.assert_called_once_with(events.AckEvent(session.id).to_client())
        mock_task.delay.assert_called_once_with(session.id, "again", self.user.id, "")

    @patch("api_app.chatbot_manager.consumers.process_chat_message")
    def test_context_url_is_forwarded_to_the_task(self, mock_task):
        consumer = _make_consumer(self.user)
        consumer.context_url = "https://intelowl.test/jobs/42"
        consumer.receive_json({"message": "summarize this"})

        session = ChatSession.objects.get(user=self.user)
        # the consumer forwards the raw context_url; the task derives the hint
        mock_task.delay.assert_called_once_with(
            session.id, "summarize this", self.user.id, "https://intelowl.test/jobs/42"
        )

    @patch("api_app.chatbot_manager.consumers.process_chat_message")
    def test_oversized_message_is_rejected(self, mock_task):
        consumer = _make_consumer(self.user)
        consumer.receive_json({"message": "x" * (events.MAX_INBOUND_MESSAGE_LEN + 1)})

        consumer.send_json.assert_called_once_with(
            events.ErrorEvent(None, events.ChatErrorDetail.INVALID_MESSAGE.value).to_client()
        )
        mock_task.delay.assert_not_called()
        # an invalid frame must not create a session
        self.assertFalse(ChatSession.objects.filter(user=self.user).exists())

    @patch("api_app.chatbot_manager.consumers.process_chat_message")
    def test_message_for_another_users_session_is_rejected(self, mock_task):
        other, _ = User.objects.get_or_create(username="other_ws_user")
        foreign_session = ChatSession.objects.create(user=other)

        consumer = _make_consumer(self.user)
        consumer.receive_json({"message": "hi", "session_id": foreign_session.id})

        consumer.send_json.assert_called_once_with(
            events.ErrorEvent(foreign_session.id, events.ChatErrorDetail.SESSION_NOT_FOUND.value).to_client()
        )
        mock_task.delay.assert_not_called()


class ChatConsumerRelayTestCase(SimpleTestCase):
    """Each group handler relays the producer's prebuilt payload verbatim to the client."""

    def test_handlers_forward_event_payload(self):
        payload = events.TokenEvent(3, "hi").to_client()
        for handler_name in ("chat_start", "chat_status", "chat_token", "chat_end", "chat_error"):
            consumer = ChatConsumer()
            consumer.send_json = MagicMock()
            getattr(consumer, handler_name)({"payload": payload})
            consumer.send_json.assert_called_once_with(payload)


class WSAuthMiddlewareTestCase(SimpleTestCase):
    """Anonymous users are closed out before the consumer is ever reached."""

    def test_anonymous_connection_is_closed_and_app_not_called(self):
        inner_app = AsyncMock()
        middleware = WSAuthMiddleware(inner_app)
        sent = []

        async def send(message):
            sent.append(message)

        scope = {"type": "websocket", "user": AnonymousUser()}
        async_to_sync(middleware)(scope, AsyncMock(), send)

        inner_app.assert_not_called()
        self.assertEqual(sent, [{"type": "websocket.close", "code": 1008}])
