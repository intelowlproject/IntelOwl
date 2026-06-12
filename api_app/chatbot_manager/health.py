# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from dataclasses import dataclass

import requests
from django.conf import settings
from django.core.cache import cache

from intel_owl.celery import app as celery_app
from intel_owl.celery import get_queue_name

logger = logging.getLogger(__name__)

# Bounds for the two liveness probes, kept small so the endpoint stays snappy under a cache miss.
WORKER_INSPECT_TIMEOUT = 1  # seconds for the Celery control broadcast round-trip
OLLAMA_PING_TIMEOUT = 3  # seconds for the Ollama HTTP probe
# The result is user-agnostic, so cache it briefly: a drawer open / multiple tabs must not re-probe.
HEALTH_CACHE_KEY = "chatbot_health"
HEALTH_CACHE_TTL = 15  # seconds; recovery is reflected within at most this window
# One user-safe message; which component is down is logged, not surfaced to the user.
HEALTH_UNAVAILABLE_DETAIL = (
    "The assistant is not available. Make sure the Ollama and chatbot services are running."
)


@dataclass
class ChatHealth:
    available: bool
    detail: str


def chatbot_health() -> ChatHealth:
    """Whether the assistant can serve a turn now (chatbot worker + Ollama), cached briefly."""
    cached = cache.get(HEALTH_CACHE_KEY)
    if cached is not None:
        return cached
    result = _compute_health()
    cache.set(HEALTH_CACHE_KEY, result, HEALTH_CACHE_TTL)
    return result


def _compute_health() -> ChatHealth:
    worker_up = _chatbot_worker_consuming()
    ollama_up = _ollama_reachable()
    if worker_up and ollama_up:
        return ChatHealth(available=True, detail="")
    logger.warning("chatbot unavailable: worker_up=%s ollama_up=%s", worker_up, ollama_up)
    return ChatHealth(available=False, detail=HEALTH_UNAVAILABLE_DETAIL)


def _chatbot_worker_consuming() -> bool:
    """True if at least one Celery worker is consuming the chatbot queue."""
    # active_queues() -> {worker: [{"name": ...}, ...]} or None when no worker replies in time.
    active = celery_app.control.inspect(timeout=WORKER_INSPECT_TIMEOUT).active_queues() or {}
    queue = get_queue_name(settings.CHATBOT_QUEUE)
    return any(q["name"] == queue for queues in active.values() for q in queues)


def _ollama_reachable() -> bool:
    """True if the Ollama daemon answers its version endpoint."""
    try:
        return requests.get(f"{settings.OLLAMA_BASE_URL}/api/version", timeout=OLLAMA_PING_TIMEOUT).ok
    except requests.RequestException:
        return False
