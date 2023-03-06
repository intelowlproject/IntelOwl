from unittest.mock import patch

from celery.canvas import Signature
from django.conf import settings
from django.core.exceptions import ValidationError

from api_app.core.classes import Plugin
from api_app.core.models import AbstractConfig
from api_app.models import Job, PluginConfig
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


@patch.multiple(
    "api_app.visualizers_manager.models.VisualizerConfig",
    analyzers=None,
    connectors=None,
)
class AbstractConfigTestCase(CustomTestCase):
    def test_abstract(self):
        with self.assertRaises(TypeError):
            AbstractConfig()

    @patch.multiple(
        "api_app.visualizers_manager.models.VisualizerConfig",
        python_path=settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH,
    )
    def test_python_class_wrong(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        self.assertEqual(
            f"{settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH}.yara.Yara",
            muc.python_complete_path,
        )
        with self.assertRaises(ImportError):
            muc.python_class
        muc.delete()

    def test_python_class(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        try:
            pc = muc.python_class
        except ImportError as e:
            self.fail(e)
        else:
            self.assertTrue(issubclass(pc, Plugin))
        finally:
            muc.delete()

    def test_clean_python_module(self):
        muc: VisualizerConfig = VisualizerConfig(
            name="test",
            description="test",
            python_module="wrong_path.WrongPath",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        with self.assertRaises(ValidationError):
            muc.full_clean()

    def test_clean_config_queue(self):
        muc: VisualizerConfig = VisualizerConfig(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "wrongQueue"},
        )
        muc.full_clean()
        self.assertEqual(muc.queue, "default")

    def test_get_verification_no_secrets(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        result = muc.get_verification()
        self.assertEqual(result["configured"], True)
        self.assertIn("details", result)
        self.assertCountEqual(result["missing_secrets"], [])
        muc.delete()

    def test_get_verification_secret_not_present(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        result = muc.get_verification()
        self.assertEqual(result["configured"], False)
        self.assertIn("details", result)
        self.assertCountEqual(result["missing_secrets"], ["test"])
        muc.delete()

    def test_get_verification_secret_not_present_not_required(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": False,
                }
            },
        )
        result = muc.get_verification()
        self.assertEqual(result["configured"], True)
        self.assertCountEqual(result["missing_secrets"], ["test"])
        muc.delete()

    def test_get_verification_secret_present(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        pc, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.user,
            organization=None,
            value="test",
            plugin_name="test",
            type="3",
            config_type="2",
        )
        result = muc.get_verification()
        self.assertEqual(result["configured"], True)
        self.assertCountEqual(result["missing_secrets"], [])
        muc.delete()

    def test_get_verification_secret_present_not_user(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        pc, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.superuser,
            organization=None,
            value="test",
            plugin_name="test",
            type="3",
            config_type="2",
        )
        result = muc.get_verification(self.user)
        self.assertEqual(result["configured"], False)
        self.assertCountEqual(result["missing_secrets"], ["test"])
        muc.delete()

    def test_is_runnable(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        self.assertTrue(muc.is_runnable())
        muc.delete()

    def test_is_runnable_disabled(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        self.assertFalse(muc.is_runnable())
        muc.delete()

    def test_is_runnable_disabled_by_org(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        org = Organization.objects.create(name="test_org")

        m = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        muc: VisualizerConfig
        muc.disabled_in_organizations.add(org)

        self.assertFalse(muc.is_runnable(self.user))

        muc.delete()
        m.delete()
        org.delete()

    def test_get_signature_disabled(self):
        job, _ = Job.objects.get_or_create(user=self.user)
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        with self.assertRaises(Exception):
            muc.get_signature(job.pk, {}, "")

        muc.delete()
        job.delete()

    def test_get_signature(self):
        job, _ = Job.objects.get_or_create(user=self.user)
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        signature = muc.get_signature(job.pk, {}, "")
        self.assertIsInstance(signature, Signature)
        muc.delete()
        job.delete()

    def test_read_plugin_config_only_user(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        pc, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.user,
            organization=None,
            value="test",
            plugin_name="test",
            type="3",
            config_type="2",
        )
        config = muc.read_secrets(self.user)
        self.assertIn("test", config.keys())
        self.assertEqual(1, len(config.keys()))
        self.assertEqual("test", config["test"])
        muc.delete()
        pc.delete()

    def test_read_plugin_config_only_org(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        org = Organization.objects.create(name="test_org")

        m = Membership.objects.create(
            user=self.user,
            organization=org,
        )

        pc, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.user,
            organization=org,
            value="testOrg",
            plugin_name="test",
            type="3",
            config_type="2",
        )
        config = muc.read_secrets(self.user)
        self.assertIn("test", config.keys())
        self.assertEqual(1, len(config.keys()))
        self.assertEqual("testOrg", config["test"])
        pc.delete()
        muc.delete()
        m.delete()
        org.delete()

    def test_read_plugin_config_user_and_org(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            secrets={
                "test": {
                    "env_var_key": "TEST_NOT_PRESENT_KEY",
                    "type": "str",
                    "description": "env_var_key",
                    "required": True,
                }
            },
        )
        org = Organization.objects.create(name="test_org")

        m = Membership.objects.create(
            user=self.user,
            organization=org,
        )

        pc, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.user,
            organization=org,
            value="testOrg",
            plugin_name="test",
            type="3",
            config_type="2",
        )
        pc2, _ = PluginConfig.objects.get_or_create(
            attribute="test",
            owner=self.user,
            organization=None,
            value="testUser",
            plugin_name="test",
            type="3",
            config_type="2",
        )

        config = muc.read_secrets(self.user)
        self.assertIn("test", config.keys())
        self.assertEqual(1, len(config.keys()))
        # user > org
        self.assertEqual("testUser", config["test"])
        pc.delete()
        pc2.delete()
        muc.delete()
        m.delete()
        org.delete()
