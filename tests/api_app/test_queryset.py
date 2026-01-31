import datetime

from django.db.models import F
from django.utils.timezone import now
from django_celery_beat.models import CrontabSchedule

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.ingestors_manager.models import IngestorConfig
from api_app.models import Job, Parameter, PluginConfig, PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class PythonConfiguQuerySetTestCase(CustomTestCase):
    def test_annotate_configured_multiple_parameter(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
            run_hash=False,
        )

        param1 = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=True,
            python_module=ac.python_module,
        )
        param2 = Parameter.objects.create(
            name="testparameter2",
            type="str",
            description="test parameter2",
            is_secret=False,
            required=True,
            python_module=ac.python_module,
        )

        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.user,
            parameter=param1,
            analyzer_config=ac,
        )
        ac_retrieved = (
            AnalyzerConfig.objects.annotate_runnable(self.user)
            .annotate(
                required_configured_params=F("required_configured_params"),
                required_params=F("required_params"),
            )
            .get(name="test")
        )

        self.assertFalse(ac_retrieved.runnable)
        self.assertEqual(2, ac_retrieved.required_params)
        self.assertEqual(1, ac_retrieved.required_configured_params)
        self.assertFalse(ac_retrieved.configured)
        pc.delete()
        param1.delete()
        param2.delete()
        ac.delete()

    def test_runnable_valid(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
            run_hash=False,
        )

        param = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=True,
            python_module=ac.python_module,
        )
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.user,
            parameter=param,
            analyzer_config=ac,
        )
        ac_retrieved = (
            AnalyzerConfig.objects.annotate_runnable(self.user)
            .annotate(
                required_configured_params=F("required_configured_params"),
                required_params=F("required_params"),
            )
            .get(name="test")
        )

        self.assertTrue(ac_retrieved.runnable)
        self.assertEqual(1, ac_retrieved.required_configured_params)
        self.assertTrue(ac_retrieved.configured)
        pc.delete()
        param.delete()
        ac.delete()

    def test_runnable_not_configured(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
            run_hash=False,
        )

        param = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=True,
            python_module=ac.python_module,
        )

        ac_retrieved = (
            AnalyzerConfig.objects.annotate_runnable(self.user)
            .annotate(
                required_configured_params=F("required_configured_params"),
                required_params=F("required_params"),
            )
            .get(name="test")
        )
        self.assertFalse(ac_retrieved.runnable)
        self.assertEqual(0, ac_retrieved.required_configured_params)
        self.assertFalse(ac_retrieved.configured)
        param.delete()
        ac.delete()

    def test_runnable_disabled(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=True,
            type="file",
            run_hash=False,
        )
        ac_retrieved = (
            AnalyzerConfig.objects.annotate_runnable(self.user)
            .annotate(
                required_configured_params=F("required_configured_params"),
                required_params=F("required_params"),
            )
            .get(name="test")
        )
        self.assertFalse(ac_retrieved.runnable)
        self.assertTrue(ac_retrieved.configured)
        self.assertEqual(0, ac_retrieved.required_configured_params)
        ac.delete()


class ParameterQuerySetTestCase(CustomTestCase):
    def test_configured_for_user(self):
        ac = AnalyzerConfig.objects.first()
        param = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=False,
            python_module=ac.python_module,
        )
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.superuser,
            parameter=param,
            analyzer_config=ac,
        )

        self.assertFalse(
            Parameter.objects.annotate_configured(ac, self.user).get(name="testparameter").configured
        )

        pc.owner = self.user
        pc.save()

        self.assertTrue(
            Parameter.objects.annotate_configured(ac, self.user).get(name="testparameter").configured
        )

        pc.delete()
        param.delete()

    def test_annotate_value_for_user(self):
        ac = AnalyzerConfig.objects.first()
        param = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=False,
            python_module=ac.python_module,
        )
        pc2 = PluginConfig.objects.create(
            value="myperfecttest2",
            for_organization=False,
            owner=None,
            parameter=param,
            analyzer_config=ac,
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.superuser, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )

        param = Parameter.objects.annotate_value_for_user(ac, self.user).get(pk=param.pk)
        self.assertFalse(hasattr(param, "owner_value"))
        self.assertFalse(hasattr(param, "org_value"))
        self.assertFalse(hasattr(param, "default_value"))
        self.assertTrue(hasattr(param, "value"))
        # default value
        self.assertEqual(param.value, "myperfecttest2")

        pc3 = PluginConfig.objects.create(
            value="myperfecttest3",
            for_organization=True,
            owner=self.superuser,
            parameter=param,
            analyzer_config=ac,
        )
        param = Parameter.objects.annotate_value_for_user(ac, self.user).get(pk=param.pk)
        # org value
        self.assertEqual(param.value, "myperfecttest3")

        pc = PluginConfig.objects.create(
            value="myperfecttest1",
            for_organization=False,
            owner=self.user,
            parameter=param,
            analyzer_config=ac,
        )
        param = Parameter.objects.annotate_value_for_user(ac, self.user).get(pk=param.pk)

        # user value
        self.assertEqual(param.value, "myperfecttest1")
        param = Parameter.objects.annotate_value_for_user(ac, self.user, {param.name: "runtime_test"}).get(
            pk=param.pk
        )
        self.assertEqual(param.value, "runtime_test")

        pc.delete()
        pc2.delete()
        pc3.delete()
        param.delete()
        m1.delete()
        m2.delete()
        org.delete()


class PluginConfigQuerySetTestCase(CustomTestCase):
    def test_visible_for_user_owner(self):
        param = Parameter.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
            type="str",
        ).first()
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.superuser,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.user).count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.superuser).count(),
        )
        pc.delete()

    def test_visible_for_user_default(self):
        param = Parameter.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
            type="str",
        ).first()
        pc = PluginConfig.objects.get_or_create(
            for_organization=False,
            owner=None,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
            defaults={"value": "myperfecttest"},
        )[0]
        self.assertEqual(
            1,
            PluginConfig.objects.visible_for_user(self.user)
            .filter(value=pc.value, analyzer_config=pc.analyzer_config)
            .count(),
        )
        pc.delete()

    def test_visible_for_user_organization(self):
        param = Parameter.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
            type="str",
        ).first()

        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.superuser,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.user).count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.superuser).count(),
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.superuser, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        pc.for_organization = True
        pc.save()
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.user).count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest").visible_for_user(self.superuser).count(),
        )

        m1.delete()
        m2.delete()
        org.delete()
        pc.delete()

    def test_admin_visible_for_own_organization(self):
        org0 = Organization.objects.create(name="test_org_0")
        org1 = Organization.objects.create(name="test_org_1")

        m0 = Membership.objects.create(user=self.superuser, organization=org0, is_owner=True)
        m1 = Membership.objects.create(user=self.admin, organization=org1, is_owner=True, is_admin=True)
        m2 = Membership.objects.create(user=self.user, organization=org1, is_owner=False, is_admin=False)
        param = Parameter.objects.filter(
            python_module__base_path=PythonModuleBasePaths.FileAnalyzer.value,
            type="str",
        ).first()

        pc0 = PluginConfig.objects.create(
            value="test_admin_visibility_0",
            for_organization=True,
            owner=self.superuser,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
        )
        pc1 = PluginConfig.objects.create(
            value="test_admin_visibility_1",
            for_organization=True,
            owner=self.user,
            parameter=param,
            analyzer_config=AnalyzerConfig.objects.filter(python_module=param.python_module).first(),
        )

        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="test_admin_visibility_0")
            .visible_for_user(self.superuser)
            .count(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="test_admin_visibility_0").visible_for_user(self.admin).count(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="test_admin_visibility_0").visible_for_user(self.user).count(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="test_admin_visibility_0").visible_for_user(self.guest).count(),
        )

        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="test_admin_visibility_1")
            .visible_for_user(self.superuser)
            .count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="test_admin_visibility_1").visible_for_user(self.admin).count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="test_admin_visibility_1").visible_for_user(self.user).count(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="test_admin_visibility_1").visible_for_user(self.guest).count(),
        )

        m0.delete()
        m1.delete()
        m2.delete()
        org0.delete()
        org1.delete()
        pc0.delete()
        pc1.delete()


class JobQuerySetTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        Job.objects.all().delete()

    def tearDown(self) -> None:
        super().tearDown()
        Job.objects.all().delete()

    def test_annotate_importance_date_this_day(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        j = Job.objects.create(
            tlp="RED",
            user=self.user,
            analyzable=an,
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(hours=5),
        )
        j = Job.objects.filter(pk=j.pk)._annotate_importance_date().first()
        self.assertEqual(3, j.date_weight)
        j.delete()
        an.delete()

    def test_annotate_importance_date_this_week(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.user,
            analyzable=an,
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(days=5),
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_date().first()
        self.assertEqual(2, j.date_weight)
        j.delete()
        an.delete()

    def test_annotate_importance_date_old(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.user,
            analyzable=an,
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(days=30),
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_date().first()
        self.assertEqual(0, j.date_weight)
        j.delete()
        an.delete()

    def test_annotate_importance_user_same_user_same_org(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.user,
            analyzable=an,
            status="reported_without_fails",
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.superuser, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_user(self.user).first()
        self.assertEqual(3, j.user_weight)
        j.delete()
        m1.delete()
        m2.delete()
        org.delete()
        an.delete()

    def test_annotate_importance_user_same_org(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.superuser,
            analyzable=an,
            status="reported_without_fails",
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.superuser, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_user(self.user).first()
        self.assertEqual(2, j.user_weight)
        j.delete()
        m1.delete()
        m2.delete()
        org.delete()
        an.delete()

    def test_annotate_importance_user_valid(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.user,
            analyzable=an,
            status="reported_without_fails",
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_user(self.user).first()
        self.assertEqual(3, j.user_weight)
        j.delete()
        an.delete()

    def test_annotate_importance_user_wrong(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        Job.objects.create(
            tlp="RED",
            user=self.superuser,
            analyzable=an,
            status="reported_without_fails",
        )
        j = Job.objects.filter(analyzable__name="test.com")._annotate_importance_user(self.user).first()
        self.assertEqual(0, j.user_weight)
        j.delete()

    def test_visible_for_user_tlp(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            analyzable=an,
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visible_for_user(self.user).count())
        j.delete()
        j = Job.objects.create(
            tlp="GREEN",
            user=self.superuser,
            analyzable=an,
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(1, Job.objects.visible_for_user(self.user).count())
        j.delete()
        an.delete()

    def test_visible_for_user_membership(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            analyzable=an,
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visible_for_user(self.user).count())
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.superuser,
            organization=org,
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(1, Job.objects.visible_for_user(self.user).count())

        m1.delete()
        m2.delete()
        org.delete()
        j.delete()
        an.delete()

    def test_visible_for_user_ingestor(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        schedule = CrontabSchedule.objects.create()
        ingestor = IngestorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Ingestor.value,
                module="threatfox.ThreatFox",
            ),
            description="test",
            disabled=False,
            schedule=schedule,
        )
        ingestor.playbooks_choice.add(PlaybookConfig.objects.first())
        j = Job.objects.create(
            tlp="RED",
            user=ingestor.user,
            analyzable=an,
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visible_for_user(self.user).count())
        ingestor.delete()
        schedule.delete()
        j.delete()
        an.delete()
