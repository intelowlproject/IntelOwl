# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from django.db.models import OuterRef, Subquery
from django.db.models.functions import Substr
from django.utils.timezone import now
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from api_app.playbooks_manager.models import PlaybookConfig
from api_app.serializers.job import ObservableAnalysisSerializer

from .agent.agent import AGENT_STOPPED_OUTPUT, build_agent_executor
from .agent.memory import DjangoChatMessageHistory
from .events import ChatErrorDetail
from .health import chatbot_health
from .models import ChatMessage, ChatSession
from .pending_action import consume_pending_analysis
from .rate_limit import _build_rate_limiter
from .serializers.analyze_observable import ConfirmAnalysisResultSerializer, flatten_errors
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

        Flow: validate the request, rate-limit per user, resolve the target
        session (or create a new one), load the prior turns from the DB as the
        agent's conversation history, invoke the tool-calling agent with the
        user's message, then persist both the user message and the assistant
        reply and return the reply. Persistence goes through
        DjangoChatMessageHistory so the ORM stays the single source of truth
        for history.
        """
        req = MessageRequestSerializer(data=request.data)
        req.is_valid(raise_exception=True)

        user_message = req.validated_data["message"]

        limiter = _build_rate_limiter()
        allowed, retry_after = limiter.allow(str(request.user.id))
        if not allowed:
            return Response(
                {
                    "errors": [
                        {
                            "detail": (f"Too many messages. Please wait {retry_after} seconds."),
                            "code": ChatErrorDetail.RATE_LIMITED.value,
                            "retry_after": retry_after,
                        }
                    ]
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        session_id = req.validated_data.get("session_id")
        if session_id:
            session = get_object_or_404(ChatSession, pk=session_id, user=request.user)
        else:
            session = ChatSession.objects.create(user=request.user)

        limiter.increment(str(request.user.id))

        history = DjangoChatMessageHistory(session=session)

        executor = build_agent_executor(user=request.user)
        try:
            result = executor.invoke(
                {"input": user_message, "chat_history": history.messages, "page_context": ""}
            )
        except Exception:  # noqa: BLE001 - any agent/Ollama failure must reach the client cleanly
            # Mirror the Celery path (tasks.py): a model/Ollama failure is surfaced as a clean
            # 503 envelope instead of an unhandled 500. session_id is included so a client that
            # created the session via this very request can keep using it.
            logger.exception(f"chatbot message: agent run failed for session {session.pk}")
            return Response(
                {"detail": ChatErrorDetail.UNAVAILABLE.value, "session_id": session.pk},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        response_text = result.get("output", "")
        if response_text == AGENT_STOPPED_OUTPUT:
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


class ChatAnalysisConfirmView(APIView):
    """Launch a previously previewed analysis. This is the ONLY path that starts an
    analyze_observable run: the agent can only preview (mint a pending id); a real user action
    (the Confirm button) posts that id here, so the model can never launch on its own (M-1)."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        pending_id = request.data.get("pending_id")
        record = consume_pending_analysis(request.user.id, pending_id) if pending_id else None
        if record is None:
            return Response(
                {
                    "errors": ["This confirmation has expired or is invalid. Ask for the analysis again."],
                    "reused": False,
                    "job": None,
                },
                status=status.HTTP_410_GONE,
            )

        # Re-apply the playbook visibility guard the preview tool uses: ObservableAnalysisSerializer
        # resolves playbook_requested via PlaybookConfig.objects.all() (no visibility filter), so
        # without this a playbook that became invisible to the user between preview and confirm could
        # still be launched.
        if (
            record.get("playbook")
            and not PlaybookConfig.objects.visible_for_user(request.user)
            .filter(name=record["playbook"])
            .exists()
        ):
            return Response(
                {
                    "errors": [f"Playbook '{record['playbook']}' is no longer visible to you."],
                    "reused": False,
                    "job": None,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = {"observable_name": record["observable_name"], "tlp": record["tlp"]}
        if record.get("playbook"):
            data["playbook_requested"] = record["playbook"]
        analyzers_list = [a.strip() for a in record.get("analyzers", "").split(",") if a.strip()]
        if analyzers_list:
            data["analyzers_requested"] = analyzers_list

        # Re-validate the observable/analyzers at launch time; playbook visibility is re-checked above.
        serializer = ObservableAnalysisSerializer(data=data, context={"request": request})
        if not serializer.is_valid(raise_exception=False):
            return Response(
                {"errors": flatten_errors(serializer.errors), "reused": False, "job": None},
                status=status.HTTP_400_BAD_REQUEST,
            )

        started = now()
        job = serializer.save(send_task=True)
        reused = job.received_request_time < started  # platform dedup returned a recent job
        return Response(
            ConfirmAnalysisResultSerializer({"errors": [], "reused": reused, "job": job}).data,
            status=status.HTTP_200_OK,
        )
