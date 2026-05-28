# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from intel_owl import secrets

OLLAMA_BASE_URL = secrets.get_secret("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = secrets.get_secret("OLLAMA_MODEL", "mistral")
CHATBOT_QUEUE = secrets.get_secret("CHATBOT_QUEUE", "chatbot")
