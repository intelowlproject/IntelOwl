# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""LangChain callback that streams a chat turn to the WebSocket as it runs.

Attached at run level (``executor.invoke(..., config={"callbacks": [handler]})``) so it sees
both the LLM token stream and the agent's tool actions, then pushes them onto the per-user
channel group via ``group_send``. Running inside the (synchronous) Celery worker means there is
no event loop, so ``async_to_sync`` is the right bridge to the async channel layer — the same
pattern ``JobConsumer.serialize_and_send_job`` already uses.
"""

import json
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from langchain_core.callbacks.base import BaseCallbackHandler

from api_app.chatbot_manager.events import (
    ActionRequiredEvent,
    ChatEvent,
    StatusEvent,
    TokenEvent,
    chat_group_for_user,
)

logger = logging.getLogger(__name__)


class ChatStreamingCallbackHandler(BaseCallbackHandler):
    """Streams the answer text token-by-token, plus a status event per tool call.

    With a tool-calling agent there is no ``Final Answer:`` marker to gate on: when the model
    decides to call a tool, the streamed chunks carry structured tool-call deltas whose *text*
    is empty (the call itself rides ``tool_call_chunks``), and when it answers it streams plain
    text. Forwarding only non-empty text therefore streams the answer while keeping tool-call
    payloads off the wire.

    This is a best-effort live view: a model may emit a short text preamble before a tool call,
    which streams and is then superseded by the actual answer. The worker persists
    ``result["output"]`` and sends it in the ``chat.end`` event, which the client treats as the
    source of truth, so the stored/displayed answer is always correct.
    """

    def __init__(self, user_id: int, session_id: int, tool_names: set[str] | None = None):
        self._group = chat_group_for_user(user_id)
        self._session_id = session_id
        # Only these tool names produce a chat.status; None means "emit any" (unit tests).
        # Filtering by the real registry suppresses LangChain's internal "_Exception" pseudo-tool
        # (and the raw error text) that handle_parsing_errors surfaces as agent actions.
        self._tool_names = tool_names
        self._channel_layer = get_channel_layer()

    def _emit(self, event: ChatEvent) -> None:
        async_to_sync(self._channel_layer.group_send)(self._group, event.as_channel_message())

    def on_llm_new_token(self, token: str, **kwargs) -> None:
        # Tool-call deltas surface here with empty text; only real answer text is forwarded.
        if token:
            self._emit(TokenEvent(self._session_id, token))

    def on_agent_action(self, action, **kwargs) -> None:
        # Fired when the agent picks a tool; action.tool is the clean tool name. Skip anything
        # that isn't a registered tool (e.g. the "_Exception" parse-error pseudo-tool, whose
        # "tool" is the raw malformed model output) so internals don't leak as chat.status.
        tool_name = getattr(action, "tool", "") or ""
        if not tool_name or (self._tool_names is not None and tool_name not in self._tool_names):
            return
        self._emit(StatusEvent(self._session_id, tool_name))

    def on_tool_end(self, output, **kwargs) -> None:
        # analyze_observable returns an envelope carrying a one-time pending_id; surface it as a
        # structured action so the frontend can render a Confirm button. Other tools have no
        # pending_id, so this is a no-op for them.
        text = getattr(output, "content", output)
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            logger.warning("on_tool_end: cannot parse tool output as JSON (%s)", type(output).__name__)
            return
        if isinstance(data, dict) and data.get("pending_id"):
            self._emit(ActionRequiredEvent(self._session_id, data["pending_id"], data.get("plan") or {}))
        else:
            logger.debug("on_tool_end: no pending_id in tool output")
