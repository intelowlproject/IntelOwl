# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from api_app.connectors_manager.models import ConnectorConfig
from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.core.models import Parameter
from api_app.core.serializers import AbstractListConfigSerializer

from .. import CustomTestCase
from ..mock_utils import MockUpRequest


class AbstractListConfigSerializerTestCase(CustomTestCase):
    def test_to_representation(self):
        cc = ConnectorConfig.objects.create(
            name="test",
            python_module="misp.MISP",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            maximum_tlp="CLEAR",
        )
        ccs = AbstractListConfigSerializer(
            context={"request": MockUpRequest(self.user)},
            child=ConnectorConfigSerializer(),
        )
        result = ccs.to_representation([cc])
        self.assertEqual(1, len(result))
        result = result[0]
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
            maximum_tlp="CLEAR",
        )
        param: Parameter = Parameter.objects.create(
            connector_config=cc,
            name="test",
            type="str",
            required=True,
            is_secret=True,
        )
        with self.assertRaises(RuntimeError):
            param.get_first_value(self.user)
        ccs = AbstractListConfigSerializer(
            context={"request": MockUpRequest(self.user)},
            child=ConnectorConfigSerializer(),
        )
        result = ccs.to_representation([cc])
        self.assertEqual(1, len(result))
        result = result[0]

        self.assertIn("verification", result)
        self.assertIn("configured", result["verification"])
        self.assertFalse(result["verification"]["configured"])
        self.assertIn("missing_secrets", result["verification"])
        self.assertEqual(1, len(result["verification"]["missing_secrets"]))
        self.assertEqual("test", result["verification"]["missing_secrets"][0])
        param.delete()
        cc.delete()
