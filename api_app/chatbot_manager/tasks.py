# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging

from asgiref.sync import async_to_sync
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Max
from django.db.models.functions import Coalesce
from django.utils.timezone import now

from api_app.chatbot_manager.agent.context import derive_page_context
from api_app.chatbot_manager.events import (
    ChatErrorDetail,
    EndEvent,
    ErrorEvent,
    StartEvent,
    chat_group_for_user,
)
from intel_owl.tasks import FailureLoggedTask

logger = logging.getLogger(__name__)


# soft_time_limit is 300s on purpose: a single chat turn can chain several tool-calling
# rounds, each one an Ollama inference on a local model, so it can legitimately take
# tens of seconds to a couple of minutes. A *soft* limit raises SoftTimeLimitExceeded
# (catchable, lets us clean up) rather than a hard time_limit that SIGKILLs the worker,
# and it bounds a hung Ollama call so it can't occupy a worker indefinitely.
@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def process_chat_message(session_id: int, user_message: str, user_id: int, context_url: str = "") -> None:
    """Run one chat turn off-request and stream it to the user's WebSocket group.

    Enqueued by ChatConsumer.receive_json. The agent runs synchronously here (so the stream can
    bridge to the async channel layer via async_to_sync) and pushes
    chat.start -> chat.status/chat.token* -> chat.end onto the per-user group, which the
    consumer relays to the browser. On any failure a single chat.error is emitted instead and
    the turn is dropped (no assistant message persisted), mirroring the sync REST path.

    Persistence is the source of truth: the streamed tokens are a live preview, while the run's
    terminal message (returned by the stream consumer) is what gets stored and sent in chat.end.
    History is snapshotted before this turn is written so the current message is not double-counted.
    """
    # The agent/LLM stack (langchain + ChatOllama) is imported lazily so the other Celery
    # workers that load this module never pay for that heavy import — only the chatbot worker,
    # which actually runs this task, does.
    from langchain_core.messages import HumanMessage
    from langgraph.errors import GraphRecursionError

    from api_app.chatbot_manager.agent.agent import RECURSION_LIMIT, build_agent
    from api_app.chatbot_manager.agent.memory import DjangoChatMessageHistory
    from api_app.chatbot_manager.agent.streaming import ChatStreamConsumer
    from api_app.chatbot_manager.models import ChatMessage, ChatSession

    channel_layer = get_channel_layer()
    group = chat_group_for_user(user_id)

    def emit(event) -> None:
        async_to_sync(channel_layer.group_send)(group, event.as_channel_message())

    # Defense in depth: never trust the task args. The session must exist AND belong to the
    # user (the consumer already enforces this, but the task must not assume that).
    try:
        session = ChatSession.objects.get(pk=session_id, user_id=user_id)
    except ChatSession.DoesNotExist:
        logger.warning(f"process_chat_message: session {session_id} not found for user {user_id}")
        emit(ErrorEvent(session_id, ChatErrorDetail.SESSION_NOT_FOUND.value))
        return

    user = get_user_model().objects.get(pk=user_id)
    history = DjangoChatMessageHistory(session=session)
    # LangChain message objects, fed straight into the prompt's chat_history
    # MessagesPlaceholder (no text pre-rendering). Evaluated here, before this turn is
    # written, so the current message is not double-counted.
    chat_history = history.messages

    emit(StartEvent(session_id))
    try:
        chat_agent = build_agent(user=user, page_context=derive_page_context(context_url))
        # Stream the run to the WebSocket. tool_names scopes which tool calls become a chat.status.
        consumer = ChatStreamConsumer(
            user_id=user_id,
            session_id=session_id,
            tool_names=chat_agent.tool_names,
        )
        # History (snapshotted before this turn is persisted) + the new user message feed the agent
        # as a messages list, the create_agent input shape.
        inputs = {"messages": [*chat_history, HumanMessage(content=user_message)]}
        response_text = consumer.run(chat_agent.runnable, inputs, {"recursion_limit": RECURSION_LIMIT})
    except SoftTimeLimitExceeded:
        logger.warning(f"process_chat_message: timed out for session {session_id}")
        emit(ErrorEvent(session_id, ChatErrorDetail.TIMEOUT.value))
        return
    except GraphRecursionError:
        # A looping model hit the recursion limit: surface a real error and drop the turn rather
        # than persisting a partial/looping run as the assistant's answer.
        logger.warning(f"process_chat_message: iteration cap hit for session {session_id}")
        emit(ErrorEvent(session_id, ChatErrorDetail.ITERATION_LIMIT.value))
        return
    except Exception as exc:  # noqa: BLE001 - any agent/Ollama failure must still reach the client
        logger.exception(f"process_chat_message: agent run failed for session {session_id}: {exc}")
        emit(ErrorEvent(session_id, ChatErrorDetail.UNAVAILABLE.value))
        return

    history.add_user_message(user_message)
    # Create the assistant row directly (rather than add_ai_message + a latest("timestamp")
    # re-query) so chat.end carries its exact id, without a lookup two overlapping turns of the
    # same session could race on.
    ai_message = ChatMessage.objects.create(
        session=session, role=ChatMessage.Role.ASSISTANT, content=response_text
    )
    emit(EndEvent(session_id, ai_message.id, response_text))


# soft_time_limit=1800: daily maintenance task whose work is a single bulk DELETE that
# cascades to ChatMessage rows. 30 minutes is generous headroom for a large backlog of stale
# sessions while still bounding a runaway query; a *soft* limit raises a catchable
# SoftTimeLimitExceeded (so the logged count stays meaningful) instead of a hard time_limit
# that SIGKILLs the worker mid-delete.
@shared_task(base=FailureLoggedTask, soft_time_limit=1800)
def delete_old_chat_sessions() -> int:
    """
    Periodic cleanup: delete ChatSessions whose last activity is older than
    CHATBOT_MESSAGE_RETENTION_DAYS. "Last activity" is the most recent message timestamp,
    falling back to created_at for sessions with no messages yet (ChatSession.updated_at is
    auto_now but is NOT touched when a ChatMessage is created, so it does not reflect activity).
    Deleting the session removes its messages via the FK on_delete=CASCADE.
    Returns the number of deleted sessions.
    """
    from api_app.chatbot_manager.models import ChatSession

    logger.info("started delete_old_chat_sessions")

    cutoff = now() - datetime.timedelta(days=settings.CHATBOT_MESSAGE_RETENTION_DAYS)
    # Coalesce(..., created_at) is required: without it, sessions with no messages get
    # last_activity = NULL and __lt never matches, so they would never be cleaned up.
    stale = ChatSession.objects.annotate(
        last_activity=Coalesce(Max("messages__timestamp"), "created_at")
    ).filter(last_activity__lt=cutoff)
    # .delete() on an annotated queryset is unreliable, so materialize the pks first and
    # delete them in a separate, un-annotated step.
    stale_pks = list(stale.values_list("pk", flat=True))
    logger.info(f"found {len(stale_pks)} stale chat sessions")
    ChatSession.objects.filter(pk__in=stale_pks).delete()  # CASCADE removes the messages

    logger.info("finished delete_old_chat_sessions")
    return len(stale_pks)
