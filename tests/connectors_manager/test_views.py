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
        self.assertEqual(response.status_code, 200)

    def test_connector_healthcheck_400(self):
        response = self.client.get("/api/connector/connector404/healthcheck")
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.json(), {"detail": "Connector doesn't exist"})


class ConnectorActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @classmethod
    def setUpClass(cls):
        super(ConnectorActionViewSetTests, cls).setUpClass()

    def setUp(self):
        super(ConnectorActionViewSetTests, self).setUp()
        self.report = self.init_report()
        self.plugin_type = "connector"

    @property
    def report_model(self):
        return ConnectorReport
