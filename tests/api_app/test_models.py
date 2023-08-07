# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from celery.canvas import Signature
from django.conf import settings
from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.classes import Plugin
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import AbstractConfig, Job, Parameter, PluginConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class AbstractConfigTestCase(CustomTestCase):
    def test_abstract(self):
        with self.assertRaises(TypeError):
            AbstractConfig()

    @patch.multiple(
        "api_app.visualizers_manager.models.VisualizerConfig",
        python_base_path=settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH,
    )
    def test_python_class_wrong(self):
        muc = VisualizerConfig(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        self.assertEqual(
            f"{settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH}.yara.Yara",
            muc.python_complete_path,
        )
        with self.assertRaises(ImportError):
            muc.python_class

    def test_python_class(self):
        muc = VisualizerConfig(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        try:
            pc = muc.python_class
        except ImportError as e:
            self.fail(e)
        else:
            self.assertTrue(issubclass(pc, Plugin))

    def test_clean_python_module(self):
        muc: VisualizerConfig = VisualizerConfig(
            name="test",
            description="test",
            python_module="wrong_path.WrongPath",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
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
            playbook=PlaybookConfig.objects.first(),
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
            playbook=PlaybookConfig.objects.first(),
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
            playbook=PlaybookConfig.objects.first(),
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
            playbook=PlaybookConfig.objects.first(),
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
            playbook=PlaybookConfig.objects.first(),
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
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
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
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        self.assertTrue(muc.is_runnable(self.user))
        muc.delete()

    def test_is_runnable_disabled(self):
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        self.assertFalse(muc.is_runnable(self.user))
        muc.delete()

    def test_is_runnable_disabled_by_org(self):
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        org = Organization.objects.create(name="test_org")

        m = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        muc: VisualizerConfig
        muc.disabled_in_organizations.add(org)
        self.assertFalse(
            VisualizerConfig.objects.filter(name="test")
            .exclude(disabled=True)
            .exclude(disabled_in_organizations=self.user.membership.organization)
        )
        self.assertFalse(muc.is_runnable(self.user))

        muc.delete()
        m.delete()
        org.delete()

    def test_get_signature_without_runnable(self):
        job, _ = Job.objects.get_or_create(user=self.user)
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        job.visualizers_to_execute.set([muc])
        gen_signature = VisualizerConfig.objects.filter(pk=muc.pk).get_signatures(job)
        with self.assertRaises(RuntimeError):
            try:
                next(gen_signature)
            except StopIteration:
                self.fail("Stop iteration should not be raised")
        muc.delete()
        job.delete()

    def test_get_signature_disabled(self):
        job, _ = Job.objects.get_or_create(user=self.user)
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=True,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
        )
        job.visualizers_to_execute.set([muc])
        gen_signature = (
            VisualizerConfig.objects.filter(pk=muc.pk)
            .annotate_runnable(self.user)
            .get_signatures(job)
        )
        with self.assertRaises(RuntimeWarning):
            try:
                next(gen_signature)
            except StopIteration:
                self.fail("Stop iteration should not be raised")
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
            playbook=PlaybookConfig.objects.first(),
        )
        job.visualizers_to_execute.set([muc])
        gen_signature = (
            VisualizerConfig.objects.filter(pk=muc.pk)
            .annotate_runnable(self.user)
            .get_signatures(job)
        )
        try:
            signature = next(gen_signature)
        except StopIteration as e:
            self.fail(e)
        self.assertIsInstance(signature, Signature)
        muc.delete()
        job.delete()


class ParameterTestCase(CustomTestCase):
    def test_clean(self):
        ac, _ = AnalyzerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara_scan.YaraScan",
            disabled=False,
            type="file",
            config={"soft_time_limit": 100, "queue": "default"},
        )
        cc, _ = ConnectorConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="misp.MISP",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
        )
        vc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module="yara.Yara",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            playbook=PlaybookConfig.objects.first(),
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
