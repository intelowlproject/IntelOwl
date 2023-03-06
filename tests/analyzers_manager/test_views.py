# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

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

    def test_organization_disable(self):
        analyzer = "ClamAV"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.post(f"{self.URL}/{analyzer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.post(f"{self.URL}/{analyzer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: AnalyzerConfig = AnalyzerConfig.objects.get(name=analyzer)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.post(f"{self.URL}/{analyzer}/organization")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(an.disabled_in_organizations.all().exists())

        response = self.client.post(f"{self.URL}/{analyzer}/organization")
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(1, an.disabled_in_organizations.all().count())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], "Plugin ClamAV already disabled")
        an.disabled_in_organizations.set([])
        m.delete()
        org.delete()

    def test_organization_enable(self):
        analyzer = "ClamAV"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.delete(f"{self.URL}/{analyzer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )
        m, _ = Membership.objects.get_or_create(
            user=self.user, organization=org, is_owner=False
        )
        response = self.client.delete(f"{self.URL}/{analyzer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: AnalyzerConfig = AnalyzerConfig.objects.get(name=analyzer)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.delete(f"{self.URL}/{analyzer}/organization")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], "Plugin ClamAV already enabled")

        an.disabled_in_organizations.add(org)
        response = self.client.delete(f"{self.URL}/{analyzer}/organization")
        self.assertEqual(response.status_code, 202)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        m.delete()
        org.delete()


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
