# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization

from .. import CustomAPITestCase


class VisualizerConfigAPITestCase(CustomAPITestCase):

    URL = "/api/visualizer"

    def test_list(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], VisualizerConfig.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        visualizer = VisualizerConfig.objects.order_by("?").first().name
        response = self.client.get(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 401)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 200)

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405)

    def test_update(self):
        visualizer = VisualizerConfig.objects.order_by("?").first().name
        response = self.client.patch(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 405)

    def test_delete(self):
        visualizer = VisualizerConfig.objects.order_by("?").first().name
        response = self.client.delete(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 405)
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{visualizer}")
        self.assertEqual(response.status_code, 405)

    def test_organization_disable(self):
        visualizer = "Yara"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.post(f"{self.URL}/{visualizer}/organization")
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
        response = self.client.post(f"{self.URL}/{visualizer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: VisualizerConfig = VisualizerConfig.objects.get(name=visualizer)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.post(f"{self.URL}/{visualizer}/organization")
        self.assertEqual(response.status_code, 201)
        self.assertTrue(an.disabled_in_organizations.all().exists())

        response = self.client.post(f"{self.URL}/{visualizer}/organization")
        self.assertEqual(response.status_code, 400, response.json())
        self.assertEqual(1, an.disabled_in_organizations.all().count())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {visualizer} already disabled"
        )
        an.disabled_in_organizations.set([])
        m.delete()
        org.delete()

    def test_organization_enable(self):
        visualizer = "Yara"
        org, _ = Organization.objects.get_or_create(name="test")
        response = self.client.delete(f"{self.URL}/{visualizer}/organization")
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
        response = self.client.delete(f"{self.URL}/{visualizer}/organization")
        # permission denied
        self.assertEqual(response.status_code, 403, response.json())
        result = response.json()
        self.assertIn("detail", result)
        self.assertEqual(
            result["detail"], "You do not have permission to perform this action."
        )

        m.is_owner = True
        m.save()
        an: VisualizerConfig = VisualizerConfig.objects.get(name=visualizer)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        response = self.client.delete(f"{self.URL}/{visualizer}/organization")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], f"Plugin {visualizer} already enabled"
        )

        an.disabled_in_organizations.add(org)
        response = self.client.delete(f"{self.URL}/{visualizer}/organization")
        self.assertEqual(response.status_code, 202)
        self.assertFalse(an.disabled_in_organizations.all().exists())
        m.delete()
        org.delete()
