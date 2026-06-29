# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from django.test import override_settings

from api_app.connectors_manager.connectors.misp import MISP
from api_app.connectors_manager.exceptions import ConnectorRunException
from tests.api_app.connectors_manager.unit_tests.base_test_class import BaseConnectorTest


class MockPyMISPClient:
    def __init__(self, *args, **kwargs):
        pass

    def add_event(self, event, *args, **kwargs):
        mock_event = MagicMock()
        mock_event.id = "51"
        mock_event.attributes = event.attributes
        return mock_event

    def get_event(self, event_id, *args, **kwargs):
        if str(event_id) == "51":
            return {
                "Event": {
                    "id": "51",
                    "info": "Intelowl Job-51: 1.2.3.4",
                    "Attribute": [
                        {
                            "id": "5",
                            "type": "ip-src",
                            "value": "1.2.3.4",
                            "event_id": "3",
                            "comment": "Analyzers Executed: FireHol_IPList",
                        },
                        {
                            "id": "6",
                            "type": "link",
                            "value": "https://misp.test/jobs/51",
                            "comment": "View Analysis on IntelOwl",
                            "event_id": "3",
                        },
                    ],
                }
            }
        return {"error": "Not Found"}


class MISPConnectorTestCase(BaseConnectorTest):
    connector_class = MISP

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "_url_key_name": "https://misp.test",
            "_api_key_name": "test-api-key",
            "tlp": "CLEAR",
            "ssl_check": False,
            "self_signed_certificate": "",
            "debug": False,
            "_job_id": 51,
        }

    def _setup_connector(self):
        connector = super()._setup_connector()

        mock_tag = MagicMock()
        mock_tag.label = "source:intelowl"
        connector._job.tags = MagicMock()
        connector._job.tags.all.return_value = [mock_tag]

        connector._job.analyzers_to_execute = MagicMock()
        connector._job.analyzers_to_execute.all.return_value.values_list.return_value = ["FireHol_IPList"]

        return connector

    @classmethod
    def get_mocked_response(cls):
        return [
            patch(
                "api_app.connectors_manager.connectors.misp.pymisp.PyMISP",
                side_effect=MockPyMISPClient,
            )
        ]

    def test_bulk_add_event_called_once(self):
        # verify that add_event is called once and that the event contains all attributes
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP") as mock_misp_cls:
            mock_instance = MagicMock()
            mock_misp_cls.return_value = mock_instance

            mock_event = MagicMock()
            mock_event.id = "51"
            mock_instance.add_event.return_value = mock_event

            connector.run()

            mock_instance.add_event.assert_called_once()
            mock_instance.add_attribute.assert_not_called()

    def test_all_attributes_present_on_event(self):
        # verify that the event sent to MISP contains the base attribute and the link attribute
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP") as mock_misp_cls:
            mock_instance = MagicMock()
            mock_misp_cls.return_value = mock_instance

            mock_event = MagicMock()
            mock_event.id = "51"
            mock_instance.add_event.return_value = MagicMock(id="51")

            connector.run()

            event_arg = mock_instance.add_event.call_args[0][0]
            attr_types = [a.type for a in event_arg.attributes]

            self.assertIn("ip-src", attr_types)
            self.assertIn("link", attr_types)

    def test_add_event_failure_raises_exception(self):
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP") as mock_misp_cls:
            mock_instance = MagicMock()
            mock_misp_cls.return_value = mock_instance

            mock_instance.add_event.side_effect = Exception("MISP unreachable")

            with self.assertRaisesRegex(ConnectorRunException, "MISP unreachable"):
                connector.run()

    def test_misp_initialisation_http_failure_raises_exception(self):
        connector = self._setup_connector()

        with patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP") as mock_misp_cls:
            mock_misp_cls.side_effect = Exception(
                "<html>The plain HTTP request was sent to HTTPS port</html>"
            )

            with self.assertRaises(ConnectorRunException) as context:
                connector.run()

            self.assertIn("plain HTTP request to an HTTPS port", str(context.exception))

    @override_settings(STAGE_CI=False, MOCK_CONNECTIONS=False)
    def test_misp_health_check_success(self):
        connector = self._setup_connector()

        mock_url_param = MagicMock()
        mock_url_param.name = "url_key_name"
        mock_url_param.value = "http://misp.test/"

        mock_api_param = MagicMock()
        mock_api_param.name = "api_key_name"
        mock_api_param.value = "dummy_api_key"

        mock_ssl_param = MagicMock()
        mock_ssl_param.name = "ssl_check"
        mock_ssl_param.value = "false"

        mock_cert_param = MagicMock()
        mock_cert_param.name = "self_signed_certificate"
        mock_cert_param.value = ""

        connector._config = MagicMock()
        connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = [
            mock_url_param,
            mock_api_param,
            mock_ssl_param,
            mock_cert_param,
        ]

        with patch("api_app.connectors_manager.connectors.misp.pymisp.PyMISP") as mock_client_cls:
            mock_instance = mock_client_cls.return_value
            mock_instance.health_check.return_value = True

            self.assertTrue(connector.health_check())

    @override_settings(STAGE_CI=False, MOCK_CONNECTIONS=False)
    def test_misp_health_check_failures(self):
        connector = self._setup_connector()

        mock_url_param = MagicMock()
        mock_url_param.name = "url_key_name"
        mock_url_param.value = "http://misp.test/"

        mock_api_param = MagicMock()
        mock_api_param.name = "api_key_name"
        mock_api_param.value = "dummy_api_key"

        connector._config = MagicMock()
        connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = [
            mock_url_param,
            mock_api_param,
        ]

        with (
            self.subTest("MISP Connection Exception"),
            patch(
                "api_app.connectors_manager.connectors.misp.pymisp.PyMISP",
                side_effect=Exception("Connection refused"),
            ),
        ):
            self.assertFalse(connector.health_check())

        with self.subTest("Missing Configuration"):
            connector._config.parameters.annotate_configured.return_value.annotate_value_for_user.return_value = []
            self.assertFalse(connector.health_check())
