# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from celery.canvas import Signature
from django.conf import settings
from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.core.classes import Plugin
from api_app.core.models import AbstractConfig, Parameter
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
        python_base_path=settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH,
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

    def test_is_configured_no_secrets(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        result = muc._is_configured(self.user)
        self.assertTrue(result)
        muc.delete()

    def test_is_configured_secret_not_present(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        param = Parameter.objects.create(
            visualizer_config=muc,
            name="test",
            type="str",
            is_secret=True,
            required=True,
        )
        result = muc._is_configured(self.user)
        self.assertFalse(result)
        param.delete()
        muc.delete()

    def test_is_configured_secret_not_present_not_required(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        param = Parameter.objects.create(
            visualizer_config=muc,
            name="test",
            type="str",
            is_secret=True,
            required=False,
        )

        result = muc._is_configured(self.user)
        param.delete()
        muc.delete()
        self.assertTrue(result)

    def test_is_configured_secret_present(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        param = Parameter.objects.create(
            visualizer_config=muc,
            name="test",
            type="str",
            is_secret=True,
            required=True,
        )

        pc, _ = PluginConfig.objects.get_or_create(
            owner=self.user, for_organization=False, parameter=param, value="test"
        )
        result = muc._is_configured(self.user)
        self.assertTrue(result)
        param.delete()
        pc.delete()
        muc.delete()

    def test_is_configured__secret_present_not_user(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        param = Parameter.objects.create(
            visualizer_config=muc,
            name="test",
            type="str",
            is_secret=True,
            required=True,
        )
        pc, _ = PluginConfig.objects.get_or_create(
            owner=self.superuser, for_organization=False, value="test", parameter=param
        )
        result = muc._is_configured(self.user)
        self.assertFalse(result)
        param.delete()
        pc.delete()
        muc.delete()

    def test_is_runnable(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        self.assertTrue(muc.is_runnable(self.user))
        muc.delete()

    def test_is_runnable_disabled(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        self.assertFalse(muc.is_runnable(self.user))
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
        job.visualizers_to_execute.set([muc])

        with self.assertRaises(Exception):
            muc.get_signature(job)

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
        job.visualizers_to_execute.set([muc])
        signature = muc.get_signature(job)
        self.assertIsInstance(signature, Signature)
        muc.delete()
        job.delete()


class ParameterTestCase(CustomTestCase):
    def test_clean(self):
        ac, _ = AnalyzerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        cc, _ = ConnectorConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        vc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        par = Parameter(
            name="test",
            analyzer_config=ac,
            connector_config=cc,
            visualizer_config=vc,
            is_secret=False,
            required=False,
            type="str",
        )
        with self.assertRaises(ValidationError):
            par.full_clean()

        par = Parameter(
            name="test",
            analyzer_config=ac,
            connector_config=cc,
            is_secret=False,
            required=False,
            type="str",
        )
        with self.assertRaises(ValidationError):
            par.full_clean()

        par = Parameter(
            name="test",
            analyzer_config=ac,
            visualizer_config=vc,
            is_secret=False,
            required=False,
            type="str",
        )
        with self.assertRaises(ValidationError):
            par.full_clean()

        par = Parameter(
            name="test",
            visualizer_config=vc,
            connector_config=cc,
            is_secret=False,
            required=False,
            type="str",
        )
        with self.assertRaises(ValidationError):
            par.full_clean()

        par = Parameter(
            name="test",
            connector_config=cc,
            is_secret=False,
            required=False,
            type="str",
        )
        par.full_clean()

    def test_get_first_value(self):
        par = Parameter(
            name="test",
            analyzer_config=AnalyzerConfig.objects.first(),
            is_secret=False,
            required=False,
            type="str",
        )
        par.full_clean()
        par.save()
        with self.assertRaises(RuntimeError):
            par.get_first_value(self.user)

        pc1 = PluginConfig.objects.create(
            value="testdefault", owner=None, for_organization=False, parameter=par
        )
        self.assertEqual("testdefault", par.get_first_value(self.user).value)

        pc2 = PluginConfig.objects.create(
            value="testorg", owner=self.superuser, for_organization=True, parameter=par
        )

        org = Organization.objects.create(name="test_org")
        m1 = Membership.objects.create(
            user=self.superuser, organization=org, is_owner=True
        )
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        self.assertEqual("testorg", par.get_first_value(self.user).value)

        pc3 = PluginConfig.objects.create(
            value="testowner", owner=self.user, for_organization=True, parameter=par
        )
        self.assertEqual("testowner", par.get_first_value(self.user).value)
        m1.delete()
        m2.delete()
        pc1.delete()
        pc2.delete()
        pc3.delete()
