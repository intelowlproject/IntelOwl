# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime
from json import loads

from celery._state import get_current_app
from celery.canvas import Signature
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django_celery_beat.models import PeriodicTask
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.connectors_manager.models import ConnectorConfig
from api_app.data_model_manager.models import DomainDataModel
from api_app.models import (
    AbstractConfig,
    Job,
    OrganizationPluginConfiguration,
    Parameter,
    PluginConfig,
    PythonModule,
)
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class OrganizationPluginConfigurationTestCase(CustomTestCase):
    def test_disable_for_rate_limit(self):
        org = Organization.objects.create(name="test_org")

        Membership.objects.create(user=self.user, organization=org, is_owner=True)

        obj = OrganizationPluginConfiguration.objects.create(
            organization=org,
            rate_limit_timeout=datetime.timedelta(minutes=1),
            config=AnalyzerConfig.objects.first(),
        )
        self.assertFalse(obj.disabled)
        self.assertIsNone(obj.rate_limit_enable_task)
        obj.disable_for_rate_limit()
        obj.refresh_from_db()
        self.assertIsNotNone(obj.rate_limit_enable_task)
        self.assertTrue(obj.disabled)
        task: PeriodicTask = obj.rate_limit_enable_task
        # retrieve the function
        function = get_current_app().tasks.get(task.task)
        # execute it
        args = loads(task.args)
        kwargs = loads(task.kwargs)
        function(*args, **kwargs)
        obj.refresh_from_db()
        self.assertFalse(obj.disabled)
        self.assertIsNone(obj.rate_limit_enable_task)
        org.delete()
        obj.delete()


class PythonModuleTestCase(CustomTestCase):
    def test_clean_python_module(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        with self.assertRaises(ValidationError):
            pc._clean_python_module()

    def test_python_complete_path(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        self.assertEqual(pc.python_complete_path, "teeest.test.Test")

    def test_str(self):
        pc = PythonModule(module="test.Test", base_path="teeest")
        self.assertEqual(str(pc), "test.Test")

    def test_unique_together(self):
        try:
            with transaction.atomic():
                PythonModule.objects.create(
                    base_path=PythonModuleBasePaths.FileAnalyzer.value,
                    module="yara_scan.YaraScan",
                )
        except IntegrityError:
            pass
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
        self.assertEqual(muc.get_routing_key(), "default")

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
        org_config = muc.get_or_create_org_configuration(org)
        org_config.disabled = True
        org_config.save()
        self.assertFalse(
            VisualizerConfig.objects.filter(name="test")
            .exclude(disabled=True)
            .exclude(orgs_configuration__organization=self.user.membership.organization)
        )
        self.assertFalse(muc.is_runnable(self.user))

        muc.delete()
        m.delete()
        org.delete()

    def test_get_signature_without_runnable(self):
        an = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job, _ = Job.objects.get_or_create(user=self.user, analyzable=an)
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
        an.delete()

    def test_get_signature_disabled(self):
        an = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job, _ = Job.objects.get_or_create(user=self.user, analyzable=an)

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
            VisualizerConfig.objects.filter(pk=muc.pk).annotate_runnable(self.user).get_signatures(job)
        )
        with self.assertRaises(RuntimeWarning):
            try:
                next(gen_signature)
            except StopIteration:
                self.fail("Stop iteration should not be raised")
        muc.delete()
        job.delete()
        an.delete()

    def test_get_signature(self):
        an = Analyzable.objects.create(name="8.8.8.8", classification=Classification.IP)
        job, _ = Job.objects.get_or_create(user=self.user, analyzable=an)

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
            VisualizerConfig.objects.filter(pk=muc.pk).annotate_runnable(self.user).get_signatures(job)
        )
        try:
            signature = next(gen_signature)
        except StopIteration as e:
            self.fail(e)
        self.assertIsInstance(signature, Signature)
        muc.delete()
        job.delete()
        an.delete()


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
    def test_get_analyzers_data_models(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        config = AnalyzerConfig.objects.first()
        domain_data_model = DomainDataModel.objects.create()
        AnalyzerReport.objects.create(
            report={
                "evaluation": "MALICIOUS",
                "urls": [{"url": "www.intelowl.com"}, {"url": "www.intelowl.com"}],
            },
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
            data_model=domain_data_model,
        )
        dms = job.get_analyzers_data_models()
        self.assertIn(domain_data_model.pk, dms.values_list("pk", flat=True))
        an1.delete()
        job.delete()

    def test_pivots_to_execute(self):
        ac = AnalyzerConfig.objects.first()
        ac2 = AnalyzerConfig.objects.exclude(pk__in=[ac.pk]).first()
        ac3 = AnalyzerConfig.objects.exclude(pk__in=[ac.pk, ac2.pk]).first()
        an = Analyzable.objects.create(
            name="test.com",
            classification="domain",
            md5="72cf478e87b031233091d8c00a38ce00",
        )
        j1 = Job.objects.create(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        pc = PivotConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path="api_app.pivots_manager.pivots",
                module="self_analyzable.SelfAnalyzable",
            ),
        )
        pc.playbooks_choice.add(PlaybookConfig.objects.first())

        j1.analyzers_to_execute.set([ac, ac2])
        pc.related_analyzer_configs.set([ac, ac2])
        self.assertCountEqual(
            j1.pivots_to_execute.filter(name="test").values_list("pk", flat=True),
            [pc.pk],
        )

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac])
        self.assertCountEqual(j1.pivots_to_execute.filter(name="test").values_list("pk", flat=True), [])

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac, ac2, ac3])
        self.assertCountEqual(
            j1.pivots_to_execute.filter(name="test").values_list("pk", flat=True),
            [pc.pk],
        )

        del j1.pivots_to_execute
        j1.analyzers_to_execute.set([ac, ac3])
        self.assertCountEqual(j1.pivots_to_execute.filter(name="test").values_list("pk", flat=True), [])

    def test_get_root_returns_self_when_is_root(self):
        """Test that get_root() returns self when the job is already a root node."""
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        root_job = Job.objects.create(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        # A newly created job should be a root
        self.assertTrue(root_job.is_root())
        self.assertEqual(root_job.get_root(), root_job)
        root_job.delete()
        an.delete()

    def test_get_root_returns_parent_for_child_job(self):
        """Test that get_root() returns the root job for a child job."""
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        root_job = Job.add_root(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        child_job = root_job.add_child(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        # Child job should return the root job
        self.assertFalse(child_job.is_root())
        self.assertEqual(child_job.get_root().pk, root_job.pk)
        child_job.delete()
        root_job.delete()
        an.delete()

    def test_get_root_deterministic_ordering(self):
        """Test that get_root() returns deterministic results using order_by('pk')."""
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        root_job = Job.add_root(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        # Call get_root multiple times and verify consistent results
        results = [root_job.get_root().pk for _ in range(10)]
        self.assertEqual(len(set(results)), 1, "get_root() should return consistent results")
        root_job.delete()
        an.delete()

    def test_get_root_handles_multiple_roots_deterministically(self):
        """
        Test that get_root() handles MultipleObjectsReturned exception
        by returning a deterministic result based on PK ordering.

        This simulates the race condition that can occur with django-treebeard
        under high concurrency. We use mocking because the path field has a
        UNIQUE constraint in the database, preventing real duplicates.
        """
        from unittest.mock import patch

        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        # Create a root job and child job
        root_job = Job.add_root(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )
        child_job = root_job.add_child(
            user=self.user,
            analyzable=an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS,
        )

        # Verify child_job is not a root (needed for the test to work)
        self.assertFalse(child_job.is_root())

        # Import MP_Node to patch its get_root method
        from treebeard.mp_tree import MP_Node

        # Patch treebeard's MP_Node.get_root to raise MultipleObjectsReturned
        # and also patch the logger to verify it was called
        with (
            patch.object(
                MP_Node,
                "get_root",
                side_effect=Job.MultipleObjectsReturned("Multiple roots found"),
            ),
            patch("api_app.models.logger") as mock_logger,
        ):
            result = child_job.get_root()

        # Verify we got a result (the fallback query should work)
        self.assertIsNotNone(result)
        # The fallback query finds root_job (the only actual root)
        self.assertEqual(result.pk, root_job.pk)

        # Verify warning was logged (using mock to avoid CI logging disable issues)
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        self.assertIn("Tree Integrity Error", call_args)
        self.assertIn("Multiple roots found", call_args)

        # Cleanup
        child_job.delete()
        root_job.delete()
        an.delete()
