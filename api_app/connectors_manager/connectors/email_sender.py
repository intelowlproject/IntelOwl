from django.core.mail import EmailMessage

from api_app.connectors_manager.classes import Connector


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
