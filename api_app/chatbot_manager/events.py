# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Wire protocol for the chat WebSocket.

Single source of truth for everything that crosses the chat WebSocket, so the producer (Celery
worker / streaming callback) and the consumer never hand-build event dicts. One style throughout:
a ``ChatEvent`` dataclass per event kind, each able to render

- ``to_client()`` — the JSON the browser receives (its ``type`` is a ``ChatEventType``), and
- ``as_channel_message()`` — that payload wrapped for a Channels ``group_send``, whose ``type``
  (``chat.token`` -> ``ChatConsumer.chat_token``) routes it to the matching consumer handler.

A chat turn streams to a per-user group (``chat-<user_id>``) rather than a per-session group: the
fixed URL ``ws/chat/?context_url=...`` carries no session id, the group key is the server-
authenticated user id (so no cross-tenant subscription is possible), and every payload carries
``session_id`` so a client with several open sessions/tabs can demultiplex.
"""

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import ClassVar, Optional

CHAT_GROUP_PREFIX = "chat-"

# Inbound guardrail: mirrors MessageRequestSerializer(message=CharField(max_length=4096)).
MAX_INBOUND_MESSAGE_LEN = 4096


class ChatEventType(StrEnum):
    """The ``type`` discriminator of an outbound frame (what the browser switches on)."""

    ACK = "ack"
    START = "start"
    STATUS = "status"
    TOKEN = "token"
    END = "end"
    ERROR = "error"


class ChatErrorDetail(StrEnum):
    """Error identifiers for the chat WebSocket.

    Most members carry human-readable text values (sent directly to the client);
    a few carry machine-oriented wire discriminators whose user-facing text is
    generated server-side (e.g. RATE_LIMITED, whose detail is built by the REST
    view with a dynamic ``retry_after`` count).
    """

    SESSION_NOT_FOUND = "Chat session not found."
    INVALID_MESSAGE = "Invalid message payload."
    TIMEOUT = "The assistant took too long to respond. Please try again."
    UNAVAILABLE = "The assistant is currently unavailable. Please try again."
    ITERATION_LIMIT = "The assistant could not complete this request. Please try rephrasing."
    RATE_LIMITED = "rate_limited"  # machine-readable code; REST view builds user-facing detail


def chat_group_for_user(user_id: int) -> str:
    """Return the per-user channel group that carries this user's chat stream."""
    return f"{CHAT_GROUP_PREFIX}{user_id}"


@dataclass(frozen=True)
class ChatEvent:
    """Base outbound chat event.

    Subclasses only declare their extra fields and set ``type``. ``to_client()`` is the frame the
    browser receives; ``as_channel_message()`` wraps it for a Channels ``group_send`` and is
    relayed verbatim by ``ChatConsumer`` (``chat.<type>`` -> the same-named handler).
    """

    # Channels routing prefix; "chat." + type -> "chat.token" -> ChatConsumer.chat_token.
    _CHANNEL_TYPE_PREFIX: ClassVar[str] = "chat."
    type: ClassVar[ChatEventType]

    session_id: Optional[int]

    def to_client(self) -> dict:
        return {"type": self.type.value, **asdict(self)}

    @property
    def channel_type(self) -> str:
        return f"{self._CHANNEL_TYPE_PREFIX}{self.type.value}"

    def as_channel_message(self) -> dict:
        return {"type": self.channel_type, "payload": self.to_client()}


@dataclass(frozen=True)
class AckEvent(ChatEvent):
    """Synchronous reply to an inbound frame, telling the client which session it landed on."""

    type: ClassVar[ChatEventType] = ChatEventType.ACK


@dataclass(frozen=True)
class StartEvent(ChatEvent):
    type: ClassVar[ChatEventType] = ChatEventType.START


@dataclass(frozen=True)
class StatusEvent(ChatEvent):
    tool: str
    type: ClassVar[ChatEventType] = ChatEventType.STATUS


@dataclass(frozen=True)
class TokenEvent(ChatEvent):
    content: str
    type: ClassVar[ChatEventType] = ChatEventType.TOKEN


@dataclass(frozen=True)
class EndEvent(ChatEvent):
    message_id: int
    content: str
    type: ClassVar[ChatEventType] = ChatEventType.END


@dataclass(frozen=True)
class ErrorEvent(ChatEvent):
    detail: str
    retry_after: Optional[int] = None
    type: ClassVar[ChatEventType] = ChatEventType.ERROR
