# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from celery.canvas import Signature
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import AbstractConfig, Job, Parameter, PluginConfig, PythonModule
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class PythonModuleTestCase(CustomTestCase):
    def test_clean_python_module(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        with self.assertRaises(ValidationError):
            pc.clean_python_module()

    def test_python_complete_path(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        self.assertEqual(pc.python_complete_path, "teeest.test.Test")

    def test_str(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        self.assertEqual(str(pc), "test.Test")

    def test_unique_together(self):
        pc = PythonModule.objects.create(module="test.Test", base_path="teeest")
        try:
            with transaction.atomic():
                PythonModule.objects.create(module="test.Test", base_path="teeest")
        except IntegrityError:
            pc.delete()
        else:
            self.fail("Duplicate module allowed")


class AbstractConfigTestCase(CustomTestCase):
    def test_abstract(self):
        with self.assertRaises(TypeError):
            AbstractConfig()

    def test_clean_config_queue(self):
        muc: VisualizerConfig = VisualizerConfig(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
            routing_key="wrong_key",
        )
        with self.assertRaises(ValidationError):
            muc.full_clean()

    def test_is_configured_no_secrets(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        result = muc._is_configured(self.user)
        self.assertTrue(result)
        muc.delete()

    def test_is_configured_secret_not_present(self):
        muc, _ = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        param = Parameter.objects.create(
            python_module=muc.python_module,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        param = Parameter.objects.create(
            python_module=muc.python_module,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        param = Parameter.objects.create(
            python_module=muc.python_module,
            name="test",
            type="str",
            is_secret=True,
            required=True,
        )

        pc, _ = PluginConfig.objects.get_or_create(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="test",
            visualizer_config=muc,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        param = Parameter.objects.create(
            python_module=muc.python_module,
            name="test",
            type="str",
            is_secret=True,
            required=True,
        )
        pc, _ = PluginConfig.objects.get_or_create(
            owner=self.superuser,
            for_organization=False,
            value="test",
            parameter=param,
            visualizer_config=muc,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        self.assertTrue(muc.is_runnable(self.user))
        muc.delete()

    def test_is_runnable_disabled(self):
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=True,
        )
        self.assertFalse(muc.is_runnable(self.user))
        muc.delete()

    def test_is_runnable_disabled_by_org(self):
        muc = VisualizerConfig.objects.create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=True,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=True,
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
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


class PluginConfigTestCase(CustomTestCase):
    def test_clean_parameter(self):
        ac, created = AnalyzerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                module="yara_scan.YaraScan",
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
            ),
            disabled=False,
            type="file",
        )
        ac2, created2 = AnalyzerConfig.objects.get_or_create(
            name="test2",
            description="test",
            python_module=PythonModule.objects.get(
                module="tranco.Tranco",
                base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
            ),
            disabled=False,
            type="file",
        )
        param = Parameter.objects.create(
            name="test",
            python_module=ac.python_module,
            is_secret=False,
            required=False,
            type="str",
        )
        pc = PluginConfig(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="test",
            analyzer_config=ac2,
        )
        with self.assertRaises(ValidationError):
            pc.clean_parameter()

        pc = PluginConfig(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="test",
            analyzer_config=ac,
        )
        pc.clean_parameter()

        if created:
            ac.delete()
        if created2:
            ac2.delete()

    def test_clean_config(self):
        ac, created = AnalyzerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                module="yara_scan.YaraScan",
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
            ),
            disabled=False,
            type="file",
        )
        cc, created2 = ConnectorConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                module="misp.MISP", base_path=PythonModuleBasePaths.Connector.value
            ),
            disabled=False,
        )
        vc, created3 = VisualizerConfig.objects.get_or_create(
            name="test",
            description="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Visualizer.value, module="yara.Yara"
            ),
            disabled=False,
        )
        param = Parameter.objects.create(
            name="test",
            python_module=ac.python_module,
            is_secret=False,
            required=False,
            type="str",
        )
        pc = PluginConfig(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="test",
            analyzer_config=ac,
            connector_config=cc,
            visualizer_config=vc,
        )
        with self.assertRaises(ValidationError):
            pc.clean_config()
        pc = PluginConfig(
            owner=self.user,
            for_organization=False,
            parameter=param,
            value="test",
            analyzer_config=ac,
            visualizer_config=vc,
        )

        with self.assertRaises(ValidationError):
            pc.clean_config()

        param.delete()
        if created:
            ac.delete()
        if created2:
            cc.delete()
        if created3:
            vc.delete()


class JobTestCase(CustomTestCase):
    def test_pivots_to_execute(self):
        ac = AnalyzerConfig.objects.first()
        ac2 = AnalyzerConfig.objects.exclude(pk__in=[ac]).first()
        ac3 = AnalyzerConfig.objects.exclude(pk__in=[ac, ac2]).first()
        j1 = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            user=self.user,
            md5="72cf478e87b031233091d8c00a38ce00",
            status=Job.Status.REPORTED_WITHOUT_FAILS,
        )
        pc = PivotConfig.objects.create(
            python_module=PythonModule.objects.get(
                base_path="api_app.pivots_manager.pivots",
                module="self_analyzable.SelfAnalyzable",
            ),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )

        j1.analyzers_to_execute.set([ac, ac2])
        pc.related_analyzer_configs.set([ac, ac2])
        self.assertCountEqual(
            j1.pivots_to_execute.values_list("pk", flat=True), [pc.pk]
        )

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac])
        self.assertCountEqual(j1.pivots_to_execute.values_list("pk", flat=True), [])

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac, ac2, ac3])
        self.assertCountEqual(
            j1.pivots_to_execute.values_list("pk", flat=True), [pc.pk]
        )

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac, ac3])
        self.assertCountEqual(j1.pivots_to_execute.values_list("pk", flat=True), [])
