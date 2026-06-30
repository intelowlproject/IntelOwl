# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict

import slack_sdk
from django.conf import settings
from slack_sdk.errors import SlackApiError

from api_app.connectors_manager.classes import Connector

logger = logging.getLogger(__name__)


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

    def health_check(self, user=None) -> bool:
        if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
            return True

        params = self._config.parameters.annotate_configured(self._config, user).annotate_value_for_user(
            self._config, user
        )
        token = None
        for param in params:
            if param.name == "token":
                token = param.value
                break

        if not token:
            logger.info("Slack health check failed: Missing token configuration.")
            return False

        try:
            client = slack_sdk.WebClient(token=token)

            # slack sdk has a built-in method (auth_test) to
            # test the authentication and connectivity to Slack
            # (auth_test returns identity information of the
            # authenticated user if the token is valid)
            # Ref: https://docs.slack.dev/tools/python-slack-sdk/reference/#slack_sdk.WebClient.auth_test
            client.auth_test()
            return True
        except Exception as e:
            logger.info(f"Slack health check failed: {e}")
            return False

    def run(self) -> dict:
        self.client.chat_postMessage(text=f"{self.title}\n{self.body}", channel=self._channel, mrkdwn=True)
        return {}
