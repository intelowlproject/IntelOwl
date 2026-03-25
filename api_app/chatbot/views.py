# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging

from asgiref.sync import sync_to_async
from django.conf import settings
from django.http import JsonResponse, StreamingHttpResponse
from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated

from .agent import run_agent
from .models import ChatMessage, ChatSession
from .prompts import build_system_prompt
from .serializers import ChatSessionSerializer, SendMessageSerializer

logger = logging.getLogger(__name__)


class ChatSessionViewSet(viewsets.ModelViewSet):
    """CRUD operations for chat sessions."""

    serializer_class = ChatSessionSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "delete"]

    def get_queryset(self):
        return ChatSession.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


def _get_token_from_request(request) -> str | None:
    """Extract the auth token string from the Authorization header."""
    auth_header = request.META.get("HTTP_AUTHORIZATION", "")
    if auth_header.startswith("Token "):
        return auth_header[6:]
    return None


async def send_message(request, session_pk):
    """Send a message and stream the assistant's response via SSE.

    This is an async Django view (not DRF) to support StreamingHttpResponse.
    Auth is handled manually by extracting the Durin token from the header.
    """
    if not getattr(settings, "CHATBOT_ENABLED", False):
        return JsonResponse(
            {"detail": "Chatbot is not enabled."},
            status=status.HTTP_404_NOT_FOUND,
        )

    if request.method != "POST":
        return JsonResponse(
            {"detail": "Method not allowed."},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    # Manual token auth for the async view.
    token_key = _get_token_from_request(request)
    if not token_key:
        return JsonResponse(
            {"detail": "Authentication credentials were not provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    from durin.models import AuthToken

    try:
        auth_token_obj = await sync_to_async(
            AuthToken.objects.select_related("user").get
        )(token=token_key)
        user = auth_token_obj.user
    except AuthToken.DoesNotExist:
        return JsonResponse(
            {"detail": "Invalid token."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Load session and verify ownership.
    try:
        session = await sync_to_async(ChatSession.objects.get)(
            id=session_pk, user=user
        )
    except ChatSession.DoesNotExist:
        return JsonResponse(
            {"detail": "Session not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # Parse request body.
    import json as _json

    try:
        body = _json.loads(request.body)
    except (ValueError, TypeError):
        return JsonResponse(
            {"detail": "Invalid JSON."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    serializer = SendMessageSerializer(data=body)
    if not serializer.is_valid():
        return JsonResponse(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_message = serializer.validated_data["message"]

    # Persist the user message.
    await sync_to_async(ChatMessage.objects.create)(
        session=session, role=ChatMessage.Role.USER, content=user_message
    )

    # Auto-title the session from the first message.
    if not session.title:
        session.title = user_message[:100]
        await sync_to_async(session.save)(update_fields=["title", "updated_at"])

    # Build conversation history from DB.
    db_messages = await sync_to_async(list)(
        session.messages.order_by("created_at").values("role", "content")
    )
    messages = [build_system_prompt(user)] + list(db_messages)

    model = getattr(settings, "CHATBOT_MODEL", "ollama/llama3.1")
    api_base = getattr(settings, "CHATBOT_API_BASE", None)

    async def event_stream():
        assistant_content = ""
        async for event in run_agent(
            messages=messages,
            model=model,
            api_base=api_base,
            auth_token=token_key,
        ):
            if event["type"] == "token":
                assistant_content += event["content"]
            yield f"data: {json.dumps(event)}\n\n"

        # Persist the assistant's complete response.
        if assistant_content:
            await sync_to_async(ChatMessage.objects.create)(
                session=session,
                role=ChatMessage.Role.ASSISTANT,
                content=assistant_content,
            )

    response = StreamingHttpResponse(
        event_stream(),
        content_type="text/event-stream",
    )
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response
