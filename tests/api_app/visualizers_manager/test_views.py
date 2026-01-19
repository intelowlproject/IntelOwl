# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type

from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomViewSetTestCase
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class VisualizerConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    URL = "/api/visualizer"

    @classmethod
    @property
    def model_class(cls) -> Type[VisualizerConfig]:
        return VisualizerConfig

    def test_get(self):
        # 1 - existing visualizer
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/DNS")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {
                "config": {"queue": "default", "soft_time_limit": 60},
                "description": "Visualize information about DNS resolvers and DNS malicious "
                "detectors",
                "disabled": True,
                "id": 1,
                "name": "DNS",
                "playbooks": ["Dns"],
                "python_module": 128,
            },
        )
        # 2 - missing visualizer
        response = self.client.get(f"{self.URL}/non_existing")
        self.assertEqual(response.status_code, 404, response.content)
        result = response.json()
        self.assertEqual(
            result, {"detail": "No VisualizerConfig matches the given query."}
        )

    def test_get_config(self):
        # 1 - existing visualizer
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/DNS/plugin_config")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(), {"organization_config": [], "user_config": []}
        )
        # 2 - missing visualizer
        response = self.client.get(f"{self.URL}/missing_visualizer/plugin_config")
        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(
            response.json(),
            {"errors": {"visualizer config": "Requested plugin does not exist."}},
        )
