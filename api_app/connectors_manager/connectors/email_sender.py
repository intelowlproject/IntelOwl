from typing import List

from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector
from intel_owl.settings import DEFAULT_FROM_EMAIL
from tests.mock_utils import if_mock_connections, patch


class EmailSender(Connector):
    sender: str
    subject: str
    header: str
    body: str
    footer: str
    CCs: List[str] = None

    def run(self) -> dict:
        if self.CCs is None:
            self.CCs = []
        if hasattr(self, "sender") and self.sender:
            sender = self.sender
        else:
            sender = DEFAULT_FROM_EMAIL
        body = self.body
        if hasattr(self, "header") and self.header:
            body = self.header + "\n\n" + body
        if hasattr(self, "footer") and self.footer:
            body = body + "\n\n" + self.footer
        base_eml = EmailMessage(
            subject=self.subject,
            from_email=sender,
            to=[self._job.analyzable.name],
            body=body,
            cc=self.CCs if self.CCs else [],
        )
        base_eml.send()
        return {
            "subject": base_eml.subject,
            "from": base_eml.from_email,
            "to": base_eml.to,
            "body": base_eml.body,
        }

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
