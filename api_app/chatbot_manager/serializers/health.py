# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers


class ChatHealthSerializer(serializers.Serializer):
    """Response shape for GET /api/chatbot/health (serializes a ChatHealth dataclass)."""

    available = serializers.BooleanField(read_only=True)
    detail = serializers.CharField(read_only=True, allow_blank=True)
