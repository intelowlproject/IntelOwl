# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.visualizers_manager.models import VisualizerConfig

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
