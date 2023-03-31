# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.connectors_manager.models import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializer

from .. import CustomTestCase
from ..mock_utils import MockUpRequest


class ConnectorConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            params={},
            secrets={},
            maximum_tlp="WHITE",
        )
        ccs = ConnectorConfigSerializer(context={"request": MockUpRequest(self.user)})
        result = ccs.to_representation(cc)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertTrue(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertFalse(result["verification"]["missing_secrets"])
        cc.delete()
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
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
            maximum_tlp="WHITE",
        )

        ccs = ConnectorConfigSerializer(context={"request": MockUpRequest(self.user)})
        result = ccs.to_representation(cc)
        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        cc.delete()
