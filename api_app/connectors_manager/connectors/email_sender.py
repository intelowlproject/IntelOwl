from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector
from tests.mock_utils import if_mock_connections, patch


class EmailSender(Connector):
    sender: str
    body: str
    subject: str

    def run(self) -> dict:
        base_eml = EmailMessage(
            subject=self.subject,
            from_email=self.sender,
            to=[],
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
