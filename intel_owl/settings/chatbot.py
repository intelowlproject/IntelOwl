# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from intel_owl import secrets

from .cache import CACHES

OLLAMA_BASE_URL = secrets.get_secret("OLLAMA_BASE_URL", "http://ollama:11434")
# qwen2.5:3b is the default on purpose: the agent relies on native tool calling, and this is
# the smallest model that proved able to pick the right tool and answer from its output with
# usable latency on a CPU-only deploy (mistral 7B took ~2.5 minutes per agent round). Stronger
# hardware can override it with any tool-capable Ollama model via the OLLAMA_MODEL secret.
OLLAMA_MODEL = secrets.get_secret("OLLAMA_MODEL", "qwen2.5:3b")
# keep_alive controls how long Ollama keeps the model resident after a request. Default -1 keeps it
# loaded indefinitely so the chatbot never re-pays the ~70s cold reload after an idle period; the
# chatbot is already opt-in (the separate ollama compose override), so an operator running it has
# accepted the model's memory cost. Constrained deploys can set a duration ("5m") or "0" (unload now).
OLLAMA_KEEP_ALIVE = secrets.get_secret("OLLAMA_KEEP_ALIVE", "-1")
CHATBOT_QUEUE = secrets.get_secret("CHATBOT_QUEUE", "chatbot")
CHATBOT_MESSAGE_RETENTION_DAYS = int(secrets.get_secret("CHATBOT_MESSAGE_RETENTION_DAYS", 90))

# Per-user rate limiting (messages / minute). Shared between REST and WebSocket;
# both paths call RateLimiter with the same backing cache, so a user who sends
# via REST and WS hits the same bucket.
CHATBOT_RATE_LIMIT = int(secrets.get_secret("CHATBOT_RATE_LIMIT", 5))
CHATBOT_RATE_LIMIT_WINDOW = int(secrets.get_secret("CHATBOT_RATE_LIMIT_WINDOW", 60))

# Separate Redis database (2) so rate-limit keys never collide with Channels (0)
# or Celery (1).  django.core.cache.backends.redis.RedisCache is built into
# Django 4.x when the redis-py extra is installed (already a transitive dep of
# channels-redis).
CACHES["chatbot_rate_limit"] = {
    "BACKEND": "django.core.cache.backends.redis.RedisCache",
    "LOCATION": "redis://redis:6379/2",
}

# Pending analyze_observable confirmations (human-in-the-loop guardrail): a preview mints a
# short-lived record; the confirm endpoint consumes it. Same Redis db as the rate limiter (2);
# keys are namespaced by prefix so they never collide.
CHATBOT_PENDING_ACTION_TTL = int(secrets.get_secret("CHATBOT_PENDING_ACTION_TTL", 600))
CACHES["chatbot_pending_action"] = {
    "BACKEND": "django.core.cache.backends.redis.RedisCache",
    "LOCATION": "redis://redis:6379/2",
}
