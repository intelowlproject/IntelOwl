# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from django.test import override_settings

from api_app.connectors_manager.connectors.slack import Slack
from tests.api_app.connectors_manager.unit_tests.base_test_class import BaseConnectorTest


class SlackTestCase(BaseConnectorTest):
    connector_class = Slack

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_channel": "ABCD",
            "slack_username": "intelowl_bot",
            "_token": "mock-token-123",
        }

    @staticmethod
    def get_mocked_response():
        return [patch("api_app.connectors_manager.connectors.slack.slack_sdk.WebClient")]

    def test_connector_run_execution(self):
        self.skipTest("Will implement later")

    @override_settings(STAGE_CI=False, MOCK_CONNECTIONS=False)
    def test_slack_health_check_success(self):
        connector = self._setup_connector()

        mock_token_param = MagicMock()
        mock_token_param.name = "token"
        mock_token_param.value = "mock-token-123"

        connector._config = MagicMock()
        connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = [
            mock_token_param
        ]

        with patch("api_app.connectors_manager.connectors.slack.slack_sdk.WebClient") as mock_webclient_cls:
            mock_instance = mock_webclient_cls.return_value
            mock_instance.auth_test.return_value = {"ok": True}

            self.assertTrue(connector.health_check())

    @override_settings(STAGE_CI=False, MOCK_CONNECTIONS=False)
    def test_slack_health_check_failures(self):
        connector = self._setup_connector()

        mock_token_param = MagicMock()
        mock_token_param.name = "token"
        mock_token_param.value = "mock-token-123"

        connector._config = MagicMock()
        connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = [
            mock_token_param
        ]

        with (
            self.subTest("Slack Connection/Token Exception"),
            patch("api_app.connectors_manager.connectors.slack.slack_sdk.WebClient") as mock_webclient_cls,
        ):
            mock_instance = mock_webclient_cls.return_value
            mock_instance.auth_test.side_effect = Exception("invalid_auth")
            self.assertFalse(connector.health_check())

        with self.subTest("Missing Token Configuration"):
            connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = []
            self.assertFalse(connector.health_check())
