# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

from .. import CustomTestCase


class RequestMockup:
    def __init__(self, user):
        self.user = user


class AnalyzerConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            params={},
            secrets={},
            type="file",
            leaks_info=False,
        )
        acs = AnalyzerConfigSerializer(context={"request": RequestMockup(self.user)})
        result = acs.to_representation(ac)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertTrue(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertFalse(result["verification"]["missing_secrets"])
        ac.delete()

        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            params={},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
            type="file",
            leaks_info=False,
        )
        acs = AnalyzerConfigSerializer(context={"request": RequestMockup(self.user)})
        result = acs.to_representation(ac)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        ac.delete()
