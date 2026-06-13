# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""WebSocket consumer for the chatbot.

Mirrors JobConsumer (api_app/websocket.py): a synchronous JsonWebsocketConsumer that joins a
channel group on connect and relays group messages to the browser. Unlike JobConsumer it is
bidirectional — the client sends a chat message over the socket and the consumer enqueues the
Celery turn — and it groups by user (chat-<user_id>) rather than by resource, because the fixed
URL ws/chat/?context_url=... carries no session id and a session belongs to exactly one user.
"""

import logging
from urllib.parse import parse_qs

from asgiref.sync import async_to_sync
from channels.generic.websocket import JsonWebsocketConsumer

from api_app.chatbot_manager.events import (
    AckEvent,
    ChatErrorDetail,
    ErrorEvent,
    chat_group_for_user,
)
from api_app.chatbot_manager.models import ChatSession
from api_app.chatbot_manager.rate_limit import _build_rate_limiter
from api_app.chatbot_manager.serializers.chat import MessageRequestSerializer
from api_app.chatbot_manager.tasks import process_chat_message

logger = logging.getLogger(__name__)


class ChatConsumer(JsonWebsocketConsumer):
    """Streams chat turns to the user and accepts inbound messages to start them.

    Auth is handled upstream by WSAuthMiddleware (anonymous users are rejected before reaching
    here). The group key is the server-authenticated scope["user"].id, so a client can only ever
    receive its own stream.
    """

    def connect(self) -> None:
        user = self.scope["user"]
        # context_url (the page the user is on) is captured and forwarded to the chat turn so the
        # agent can resolve "this job/investigation" references (see derive_page_context in tasks.py).
        self.context_url = self._parse_context_url()
        self.group_name = chat_group_for_user(user.id)
        self.accept()
        async_to_sync(self.channel_layer.group_add)(self.group_name, self.channel_name)
        logger.debug(f"user {user} connected to chat group {self.group_name}")

    def disconnect(self, close_code) -> None:
        group_name = getattr(self, "group_name", None)
        if group_name:
            async_to_sync(self.channel_layer.group_discard)(group_name, self.channel_name)
        logger.debug(f"chat ws disconnected (group={group_name}, code={close_code})")

    def receive_json(self, content, **kwargs) -> None:
        """Validate one inbound message, resolve its session, and enqueue the agent turn.

        The frame is untrusted: it is validated/length-capped by
        MessageRequestSerializer, and any supplied session_id is resolved scoped
        to the connected user, so a client cannot drive another user's session.
        Rate limiting is enforced before session resolution so a rate-limited
        client cannot create sessions by sending messages that are then dropped.
        """
        user = self.scope["user"]
        serializer = MessageRequestSerializer(data=content)
        if not serializer.is_valid():
            self.send_json(ErrorEvent(None, ChatErrorDetail.INVALID_MESSAGE.value).to_client())
            return

        limiter = _build_rate_limiter()
        allowed, retry_after = limiter.allow(str(user.id))
        if not allowed:
            self.send_json(
                ErrorEvent(None, ChatErrorDetail.RATE_LIMITED.value, retry_after=retry_after).to_client()
            )
            return

        session_id = serializer.validated_data.get("session_id")
        message = serializer.validated_data["message"]
        try:
            session = self._resolve_session(user, session_id)
        except ChatSession.DoesNotExist:
            self.send_json(ErrorEvent(session_id, ChatErrorDetail.SESSION_NOT_FOUND.value).to_client())
            return

        limiter.increment(str(user.id))

        # Ack the (possibly newly created) session id before the asynchronous stream begins.
        self.send_json(AckEvent(session.id).to_client())
        process_chat_message.delay(session.id, message, user.id, self.context_url)

    @staticmethod
    def _resolve_session(user, session_id) -> ChatSession:
        """Return the user's existing session, or create a fresh one when none is given."""
        if session_id is None:
            return ChatSession.objects.create(user=user)
        return ChatSession.objects.get(pk=session_id, user=user)

    def _parse_context_url(self) -> str:
        query_string = self.scope.get("query_string", b"").decode()
        return parse_qs(query_string).get("context_url", [""])[0]

    # Group handlers: Channels maps an event "type" (e.g. "chat.token") to the same-named method
    # with dots turned into underscores. Each one relays the payload the producer already built.
    def chat_start(self, event) -> None:
        self.send_json(event["payload"])

    def chat_status(self, event) -> None:
        self.send_json(event["payload"])

    def chat_token(self, event) -> None:
        self.send_json(event["payload"])

    def chat_end(self, event) -> None:
        self.send_json(event["payload"])

    def chat_error(self, event) -> None:
        self.send_json(event["payload"])
