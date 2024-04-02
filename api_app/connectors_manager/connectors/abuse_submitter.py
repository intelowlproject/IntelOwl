from api_app.connectors_manager.classes import Connector


class AbuseSubmitter(Connector):
    email_receiver: str

    @property
    def body(self) -> str:
        return "Email body"

    def run(self) -> dict:
        return {}
