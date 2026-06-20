from typing import Dict

import slack_sdk
from slack_sdk.errors import SlackApiError

from api_app.connectors_manager.classes import Connector


class Slack(Connector):
    _channel: str
    slack_username: str
    _token: str

    def get_exceptions_to_catch(self) -> list:
        elems = super().get_exceptions_to_catch()
        return elems + [SlackApiError]

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.client = slack_sdk.WebClient(token=self._token)

    @property
    def title(self) -> str:
        return "*IntelOwl analysis*"

    @property
    def body(self) -> str:
        return (
            "Analysis executed "
            f"{f'by <@{self.slack_username}> ' if self.slack_username else ''}"
            f"for <{self._job.url}/raw|{self._job.analyzable.name}>"
        )

    def run(self) -> dict:
        self.client.chat_postMessage(text=f"{self.title}\n{self.body}", channel=self._channel, mrkdwn=True)
        return {}
