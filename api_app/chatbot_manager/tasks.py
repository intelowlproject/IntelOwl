# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import logging

from celery import shared_task
from django.conf import settings
from django.db.models import Max
from django.db.models.functions import Coalesce
from django.utils.timezone import now

from intel_owl.tasks import FailureLoggedTask

logger = logging.getLogger(__name__)


# soft_time_limit is 300s on purpose: a single chat turn can chain several ReAct
# iterations, each one an Ollama inference on a local model, so it can legitimately take
# tens of seconds to a couple of minutes. A *soft* limit raises SoftTimeLimitExceeded
# (catchable, lets us clean up) rather than a hard time_limit that SIGKILLs the worker,
# and it bounds a hung Ollama call so it can't occupy a worker indefinitely.
@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def process_chat_message(session_id: int, user_message: str, user_id: int) -> str:
    # TODO: full async implementation via the WebSocket consumer + Celery task.
    raise NotImplementedError


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
