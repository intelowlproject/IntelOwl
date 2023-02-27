# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class ConnectorConfigAPITestCase(CustomAPITestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0003_connector_pluginconfig.json",
    ]
    URL = "/api/connector"

    def test_list(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], ConnectorConfig.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 401)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 200)

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405)

    def test_update(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)

    def test_delete(self):
        connector = ConnectorConfig.objects.order_by("?").first().name
        response = self.client.delete(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{connector}")
        self.assertEqual(response.status_code, 405)

    def test_health_check(self):
        connector: ConnectorConfig = ConnectorConfig.objects.get(name="YETI")
        self.assertTrue(connector.is_runnable())
        self.assertIsNotNone(connector.read_secrets().get("url_key_name", None))
        response = self.client.get(f"{self.URL}/{connector.name}/health_check")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{connector.name}/health_check")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)
        self.assertTrue(result["status"])


class ConnectorActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0003_connector_pluginconfig.json",
    ]

    @property
    def plugin_type(self):
        return "connector"

    @property
    def report_model(self):
        return ConnectorReport
