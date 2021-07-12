# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.connectors_manager.serializers import ConnectorConfigSerializer

from .. import CustomAPITestCase


class ConnectorAppViewsTestCase(CustomAPITestCase):
    def test_get_connector_config(self):
        response = self.client.get("/api/get_connector_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), ConnectorConfigSerializer.read_and_verify_config()
        )
