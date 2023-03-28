from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from api_app.connectors_manager.classes import Connector


class Slack(Connector):
    _channel: str
    slack_username: str = None
    _token: str

    def get_exceptions_to_catch(self) -> list:
        elems = super().get_exceptions_to_catch()
        return elems + [SlackApiError]

    def config(self):
        super().config()
        self.client = WebClient(token=self._token)

    @property
    def title(self) -> str:
        return "*IntelOwl analysis*"

    @property
    def body(self) -> str:
        return (
            f"Analysis executed "
            f"{f'by <@{self.slack_username}> ' if self.slack_username else ''}"
            f"for <{self._job.url}|{self._job.analyzed_object_name}>"
        )

    def run(self) -> dict:
        self.client.chat_postMessage(
            text=f"{self.title}\n{self.body}", channel=self._channel, mrkdwn=True
        )
        return {}
