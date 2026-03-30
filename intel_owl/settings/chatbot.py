# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ._util import get_secret

# Feature flag — disabled by default. Enable via environment variable.
CHATBOT_ENABLED = get_secret("CHATBOT_ENABLED", "False") == "True"

# LLM configuration (litellm model string).
# Default: local Ollama. Override for cloud providers, e.g. "gpt-4o".
CHATBOT_MODEL = get_secret("CHATBOT_MODEL", "ollama/llama3.1")
CHATBOT_API_BASE = get_secret("CHATBOT_API_BASE", "http://ollama:11434")
CHATBOT_MAX_TOKENS = int(get_secret("CHATBOT_MAX_TOKENS", "4096"))
CHATBOT_TEMPERATURE = float(get_secret("CHATBOT_TEMPERATURE", "0.1"))

# Internal base URL for IntelOwl API self-calls from tools.
CHATBOT_INTELOWL_BASE_URL = get_secret("CHATBOT_INTELOWL_BASE_URL", "http://uwsgi:8001")

# Session management.
CHATBOT_SESSION_TTL_HOURS = int(get_secret("CHATBOT_SESSION_TTL_HOURS", "72"))
CHATBOT_MAX_MESSAGES_PER_SESSION = int(get_secret("CHATBOT_MAX_MESSAGES_PER_SESSION", "100"))
