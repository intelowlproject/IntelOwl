from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector
from intel_owl.settings import DEFAULT_FROM_EMAIL
from tests.mock_utils import if_mock_connections, patch


class EmailSender(Connector):
    sender: str
    subject: str
    body: str

    def run(self) -> dict:
        if self.sender:
            sender = self.sender
        else:
            sender = DEFAULT_FROM_EMAIL
        base_eml = EmailMessage(
            subject=self.subject,
            from_email=sender,
            to=[self._job.observable_name],
            body=self.body,
        )
        base_eml.send()
        return {"receiver": self._job.observable_name}

    def update(self) -> bool:
        pass

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
