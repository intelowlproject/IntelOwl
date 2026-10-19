# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.choices import PythonModuleBasePaths
from api_app.models import Parameter, PluginConfig, PythonModule
from api_app.visualizers_manager.models import VisualizerConfig
from tests import CustomTestCase


class PluginConfigEncryptionTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.vc, _ = VisualizerConfig.objects.get_or_create(
            name="test_encryption",
            description="test encryption",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value,
                module="yara.Yara",
            ),
            disabled=False,
        )
        self.secret_param = Parameter.objects.create(
            python_module=self.vc.python_module,
            name="test_api_key",
            type="str",
            is_secret=True,
            required=False,
        )
        self.non_secret_param = Parameter.objects.create(
            python_module=self.vc.python_module,
            name="test_max_retries",
            type="int",
            is_secret=False,
            required=False,
        )

    def tearDown(self):
        self.secret_param.delete()
        self.non_secret_param.delete()
        self.vc.delete()
        super().tearDown()

    def test_secret_value_encrypted_on_save(self):
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=self.secret_param,
            value="my_super_secret_api_key_12345",
            visualizer_config=self.vc,
        )
        pc.refresh_from_db()
        self.assertIsInstance(pc.value, str)
        self.assertTrue(pc.value.startswith("gAAAAA"))
        pc.delete()

    def test_encrypt_decrypt_roundtrip(self):
        original = "my_super_secret_api_key_12345"
        encrypted = PluginConfig._encrypt_value(original)
        self.assertTrue(encrypted.startswith("gAAAAA"))
        self.assertEqual(PluginConfig._decrypt_value(encrypted), original)

    def test_non_secret_value_unchanged(self):
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=self.non_secret_param,
            value=10,
            visualizer_config=self.vc,
        )
        pc.refresh_from_db()
        self.assertEqual(pc.value, 10)
        pc.delete()

    def test_no_double_encryption(self):
        pc = PluginConfig.objects.create(
            owner=self.user,
            for_organization=False,
            parameter=self.secret_param,
            value="test_secret_value",
            visualizer_config=self.vc,
        )
        pc.refresh_from_db()
        first_encrypted = pc.value

        # saving again should not re-encrypt
        pc.save()
        pc.refresh_from_db()
        self.assertEqual(pc.value, first_encrypted)
        self.assertEqual(PluginConfig._decrypt_value(pc.value), "test_secret_value")
        pc.delete()

    def test_encrypt_decrypt_dict(self):
        original = {"key": "value", "nested": {"a": 1}}
        encrypted = PluginConfig._encrypt_value(original)
        self.assertTrue(encrypted.startswith("gAAAAA"))
        self.assertEqual(PluginConfig._decrypt_value(encrypted), original)

    def test_encrypt_decrypt_list(self):
        original = ["secret1", "secret2", "secret3"]
        encrypted = PluginConfig._encrypt_value(original)
        self.assertTrue(encrypted.startswith("gAAAAA"))
        self.assertEqual(PluginConfig._decrypt_value(encrypted), original)
