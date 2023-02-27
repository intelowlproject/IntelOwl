# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class AnalyzerConfigAPITestCase(CustomAPITestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0002_analyzer_pluginconfig.json",
    ]

    URL = "/api/analyzer"

    def test_list(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], AnalyzerConfig.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        analyzer = AnalyzerConfig.objects.order_by("?").first().name
        response = self.client.get(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 401)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 200)

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405)

    def test_update(self):
        analyzer = AnalyzerConfig.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 405)

    def test_delete(self):
        analyzer = AnalyzerConfig.objects.order_by("?").first().name
        response = self.client.delete(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{analyzer}")
        self.assertEqual(response.status_code, 405)

    def test_pull(self):
        analyzer = "Yara"
        response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)

        response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 200, response.json())
        result = response.json()
        self.assertIn("status", result)
        self.assertTrue(result["status"])

        analyzer = "Xlm_Macro_Deobfuscator"
        response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], "No update implemented")

    def test_health_check(self):
        analyzer = "ClamAV"
        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)

        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)
        self.assertTrue(result["status"])

        analyzer = "Xlm_Macro_Deobfuscator"
        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], "No healthcheck implemented")


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
        "api_app/fixtures/0002_analyzer_pluginconfig.json",
    ]

    @property
    def plugin_type(self):
        return "analyzer"

    @property
    def report_model(self):
        return AnalyzerReport
