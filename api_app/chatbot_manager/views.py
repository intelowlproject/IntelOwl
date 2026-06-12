# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from django.db.models import OuterRef, Subquery
from django.db.models.functions import Substr
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from .agent.agent import AGENT_STOPPED_OUTPUT, build_agent_executor
from .agent.memory import DjangoChatMessageHistory
from .events import ChatErrorDetail
from .health import chatbot_health
from .models import ChatMessage, ChatSession
from .serializers.chat import (
    ChatMessageSerializer,
    ChatSessionSerializer,
    MessageRequestSerializer,
    MessageResponseSerializer,
)
from .serializers.health import ChatHealthSerializer

logger = logging.getLogger(__name__)


class ChatSessionViewSet(ModelViewSet):
    serializer_class = ChatSessionSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "delete", "head", "options"]

    # Max characters for the annotated session title; keeps list rows single-line.
    SESSION_TITLE_MAX_LEN = 40

    def get_queryset(self):
        qs = ChatSession.objects.filter(user=self.request.user)
        # Annotate a title only when listing — single-object GETs (detail/messages) don't need it
        # and the extra Subquery would be wasted work.
        if self.action == "list":
            first_user_msg = (
                ChatMessage.objects.filter(
                    session=OuterRef("pk"),
                    role=ChatMessage.Role.USER,
                )
                .order_by("timestamp")
                .values("content")[:1]
            )
            qs = qs.annotate(
                _raw_title=Subquery(first_user_msg),
                title=Substr("_raw_title", 1, self.SESSION_TITLE_MAX_LEN),
            )
        return qs

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["post"], url_path="message")
    def message(self, request):
        """Run one synchronous chat turn against the agent.

        Flow: validate the request, resolve the target session (or create a new one),
        load the prior turns from the DB as the agent's conversation history, invoke the
        tool-calling agent with the user's message, then persist both the user message and
        the assistant reply and return the reply. Persistence goes through
        DjangoChatMessageHistory so the ORM stays the single source of truth for history.
        """
        req = MessageRequestSerializer(data=request.data)
        req.is_valid(raise_exception=True)

        session_id = req.validated_data.get("session_id")
        user_message = req.validated_data["message"]

        if session_id:
            session = get_object_or_404(ChatSession, pk=session_id, user=request.user)
        else:
            session = ChatSession.objects.create(user=request.user)

        history = DjangoChatMessageHistory(session=session)

        executor = build_agent_executor(user=request.user)
        # history.messages are LangChain message objects, fed straight into the prompt's
        # chat_history MessagesPlaceholder; read before this turn is persisted below.
        result = executor.invoke({"input": user_message, "chat_history": history.messages})
        response_text = result.get("output", "")
        if response_text == AGENT_STOPPED_OUTPUT:
            # max_iterations force-stopped a looping model: return an error and drop the turn
            # rather than persisting LangChain's canned string as the assistant's answer
            # (mirrors the WebSocket path's chat.error semantics, session_id included so the
            # client can keep using a session created by this very request).
            logger.warning(f"chatbot message: iteration cap hit for session {session.pk}")
            return Response(
                {"detail": ChatErrorDetail.ITERATION_LIMIT.value, "session_id": session.pk},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        history.add_user_message(user_message)
        history.add_ai_message(response_text)
        ai_msg = ChatMessage.objects.filter(session=session, role=ChatMessage.Role.ASSISTANT).latest(
            "timestamp"
        )

        return Response(
            MessageResponseSerializer(ai_msg).data,
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["get"], url_path="messages")
    def messages(self, request, pk=None):
        """Return a chat session's messages, oldest first, paginated.

        `self.get_object()` resolves the session through `get_queryset()`, which is
        already scoped to `request.user`, so another user's session yields a 404 for
        free (no manual ownership check). Messages are ordered by `timestamp` ascending
        so the frontend can render the conversation top-to-bottom when a chat is reopened.

        Pagination is not automatic inside a custom @action (DRF only paginates the
        default `list`), so it is driven explicitly via `paginate_queryset` /
        `get_paginated_response`, mirroring the project's CustomPageNumberPagination
        default. The `page is None` branch is the idiomatic fallback for when pagination
        is disabled.
        """
        session = self.get_object()
        queryset = session.messages.order_by("timestamp")

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ChatMessageSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = ChatMessageSerializer(queryset, many=True)
        return Response(serializer.data)


class ChatHealthView(APIView):
    """Proactive availability probe for the chat panel (chatbot worker + Ollama)."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(ChatHealthSerializer(chatbot_health()).data)
