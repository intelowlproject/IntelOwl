# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.chat_history import BaseChatMessageHistory
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage


class DjangoChatMessageHistory(BaseChatMessageHistory):
    """LangChain chat history backed by Django ChatMessage model."""

    def __init__(self, session):
        self.session = session

    @property
    def messages(self) -> list[BaseMessage]:
        from api_app.chatbot_manager.models import ChatMessage

        result = []
        for msg in ChatMessage.objects.filter(session=self.session).order_by("timestamp"):
            if msg.role == ChatMessage.Role.USER:
                result.append(HumanMessage(content=msg.content))
            else:
                result.append(AIMessage(content=msg.content))
        return result

    def add_message(self, message: BaseMessage) -> None:
        from api_app.chatbot_manager.models import ChatMessage

        role = ChatMessage.Role.USER if isinstance(message, HumanMessage) else ChatMessage.Role.ASSISTANT
        ChatMessage.objects.create(session=self.session, role=role, content=message.content)

    def clear(self) -> None:
        from api_app.chatbot_manager.models import ChatMessage

        ChatMessage.objects.filter(session=self.session).delete()
