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
