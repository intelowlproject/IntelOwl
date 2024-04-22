from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector
from tests.mock_utils import if_mock_connections, patch


class EmailSender(Connector):
    sender: str

    @property
    def subject(self) -> str:
        return f"Take down domain {self._job.parent_job.parent_job.observable_name}"

    @property
    def body(self) -> str:
        return (
            f"Domain {self._job.parent_job.parent_job.observable_name} "
            f"has been reported as malicious. We request you to take it down."
        )

    def run(self) -> dict:
        base_eml = EmailMessage(
            subject=self.subject,
            from_email=self.sender,
            to=[self._job.observable_name],
            body=self.body,
        )
        base_eml.send()
        return {"receiver": self._job.observable_name}

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
