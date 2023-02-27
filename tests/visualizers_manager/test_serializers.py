# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.visualizers_manager.models import VisualizerConfig
from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

from .. import CustomTestCase


class RequestMockup:
    def __init__(self, user):
        self.user = user


class VisualizerConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        vc = VisualizerConfig.objects.create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            analyzers=[],
            connectors=[],
        )
        vcs = VisualizerConfigSerializer(context={"request": RequestMockup(self.user)})
        result = vcs.to_representation(vc)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertTrue(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertFalse(result["verification"]["missing_secrets"])
        vc.delete()
        vc = VisualizerConfig.objects.create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            analyzers=[],
            connectors=[],
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )

        vcs = ConnectorConfigSerializer(context={"request": RequestMockup(self.user)})
        result = vcs.to_representation(vc)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        vc.delete()
