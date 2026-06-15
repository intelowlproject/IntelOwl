# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Short-lived store for pending analyze_observable confirmations (HITL guardrail).

A preview mints a record keyed by a random id; the confirm endpoint consumes it (one-shot,
user-scoped). Backed by a dedicated Redis cache so the model can never launch an analysis on
its own -- only a real user action presenting a valid pending id can.
"""

import uuid

from django.conf import settings
from django.core.cache import caches

CACHE_ALIAS = "chatbot_pending_action"
_KEY_PREFIX = "chatbot_pending_"


def create_pending_analysis(user_id: int, payload: dict) -> str:
    """Store the previewed analysis inputs and return a fresh one-time pending id."""
    pending_id = uuid.uuid4().hex
    record = {"user_id": user_id, "payload": payload}
    caches[CACHE_ALIAS].set(_key(pending_id), record, timeout=settings.CHATBOT_PENDING_ACTION_TTL)
    return pending_id


def consume_pending_analysis(user_id: int, pending_id: str) -> dict | None:
    """Return and delete the pending payload iff it exists and belongs to `user_id` (one-shot)."""
    cache = caches[CACHE_ALIAS]
    key = _key(pending_id)
    record = cache.get(key)
    if not record or record.get("user_id") != user_id:
        return None
    # delete() reports whether the key still existed: under a concurrent double-submit only the
    # caller whose delete actually removed it proceeds, keeping the launch strictly one-shot.
    if not cache.delete(key):
        return None
    return record["payload"]


def _key(pending_id: str) -> str:
    return f"{_KEY_PREFIX}{pending_id}"
