from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector
from tests.mock_utils import if_mock_connections, patch


class EmailSender(Connector):
    receiver: str
    sender: str

    @property
    def body(self) -> str:
        return "Email body"

    def run(self) -> dict:
        base_eml = EmailMessage(
            subject="Takedown domain",
            from_email=self.sender,
            to=[self.receiver],
            body=self.body,
        )
        base_eml.send()
        return {}

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "django.core.mail.EmailMessage.send",
                    return_value="Email sent",
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
