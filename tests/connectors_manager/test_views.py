# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.connectors_manager.models import ConnectorReport
from api_app.connectors_manager.serializers import ConnectorConfigSerializer

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class ConnectorAppViewsTestCase(CustomAPITestCase):
    def test_get_connector_config(self):
        response = self.client.get("/api/get_connector_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), ConnectorConfigSerializer.read_and_verify_config()
        )

    def test_connector_healthcheck_200(self):
        response = self.client.get("/api/connector/OpenCTI/healthcheck")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_connector_healthcheck_400(self):
        response = self.client.get("/api/connector/connector404/healthcheck")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "Connector doesn't exist"}, msg=msg
        )


class ConnectorActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @property
    def plugin_type(self):
        return "connector"

    @property
    def report_model(self):
        return ConnectorReport
