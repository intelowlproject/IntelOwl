# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from .models import ChatMessage, ChatSession


class ChatMessageSerializer(rfs.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ["id", "role", "content", "created_at"]
        read_only_fields = fields


class ChatSessionSerializer(rfs.ModelSerializer):
    message_count = rfs.SerializerMethodField()

    class Meta:
        model = ChatSession
        fields = ["id", "title", "created_at", "updated_at", "message_count"]
        read_only_fields = ["id", "created_at", "updated_at"]

    def get_message_count(self, obj) -> int:
        return obj.messages.count()


class SendMessageSerializer(rfs.Serializer):
    message = rfs.CharField(max_length=10000, required=True)
