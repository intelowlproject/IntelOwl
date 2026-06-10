# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from intel_owl import secrets

OLLAMA_BASE_URL = secrets.get_secret("OLLAMA_BASE_URL", "http://ollama:11434")
# qwen2.5:3b is the default on purpose: the agent relies on native tool calling, and this is
# the smallest model that proved able to pick the right tool and answer from its output with
# usable latency on a CPU-only deploy (mistral 7B took ~2.5 minutes per agent round). Stronger
# hardware can override it with any tool-capable Ollama model via the OLLAMA_MODEL secret.
OLLAMA_MODEL = secrets.get_secret("OLLAMA_MODEL", "qwen2.5:3b")
CHATBOT_QUEUE = secrets.get_secret("CHATBOT_QUEUE", "chatbot")
CHATBOT_MESSAGE_RETENTION_DAYS = int(secrets.get_secret("CHATBOT_MESSAGE_RETENTION_DAYS", 90))
