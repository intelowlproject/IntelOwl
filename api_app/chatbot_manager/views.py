# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .agent.agent import build_agent_executor, format_history
from .agent.memory import DjangoChatMessageHistory
from .models import ChatMessage, ChatSession
from .serializers import (
    ChatSessionSerializer,
    MessageRequestSerializer,
    MessageResponseSerializer,
)


class ChatSessionViewSet(ModelViewSet):
    serializer_class = ChatSessionSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        return ChatSession.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["post"], url_path="message")
    def message(self, request):
        req = MessageRequestSerializer(data=request.data)
        req.is_valid(raise_exception=True)

        session_id = req.validated_data.get("session_id")
        user_message = req.validated_data["message"]

        if session_id:
            session = get_object_or_404(ChatSession, pk=session_id, user=request.user)
        else:
            session = ChatSession.objects.create(user=request.user)

        history = DjangoChatMessageHistory(session=session)
        chat_history_text = format_history(history.messages)

        executor = build_agent_executor(user=request.user)
        result = executor.invoke({"input": user_message, "chat_history": chat_history_text})
        response_text = result.get("output", "")

        ChatMessage.objects.create(
            session=session,
            role=ChatMessage.Role.USER,
            content=user_message,
        )
        ai_msg = ChatMessage.objects.create(
            session=session,
            role=ChatMessage.Role.ASSISTANT,
            content=response_text,
        )

        return Response(
            MessageResponseSerializer(
                {
                    "session_id": session.pk,
                    "response": response_text,
                    "message_id": ai_msg.pk,
                }
            ).data,
            status=status.HTTP_200_OK,
        )
