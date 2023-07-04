import datetime

from django.utils.timezone import now

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job, Parameter, PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class PythonConfiguQuerySetTestCase(CustomTestCase):
    def test_runnable_valid(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
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
            analyzer_config=ac,
        )
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.user,
            parameter=param,
        )
        ac_retrieved = AnalyzerConfig.objects.annotate_runnable(self.user).get(
            name="test"
        )

        self.assertTrue(ac_retrieved.runnable)
        self.assertEqual(1, ac_retrieved.configured_required_params)
        self.assertTrue(ac_retrieved.configured)
        pc.delete()
        param.delete()
        ac.delete()

    def test_runnable_not_configured(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
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
            analyzer_config=ac,
        )

        ac_retrieved = AnalyzerConfig.objects.annotate_runnable(self.user).get(
            name="test"
        )
        self.assertFalse(ac_retrieved.runnable)
        self.assertEqual(0, ac_retrieved.configured_required_params)
        self.assertFalse(ac_retrieved.configured)
        param.delete()
        ac.delete()

    def test_runnable_disabled(self):
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=True,
            type="file",
            run_hash=False,
        )
        ac_retrieved = AnalyzerConfig.objects.annotate_runnable(self.user).get(
            name="test"
        )
        self.assertFalse(ac_retrieved.runnable)
        self.assertTrue(ac_retrieved.configured)
        self.assertEqual(0, ac_retrieved.configured_required_params)
        ac.delete()


class ParameterQuerySetTestCase(CustomTestCase):
    def test_configured_for_user(self):
        param = Parameter.objects.create(
            name="testparameter",
            type="str",
            description="test parameter",
            is_secret=False,
            required=False,
            analyzer_config=AnalyzerConfig.objects.first(),
        )
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.superuser,
            parameter=param,
        )

        self.assertFalse(
            Parameter.objects.annotate_configured(self.user)
            .get(name="testparameter")
            .configured
        )

        pc.owner = self.user
        pc.save()

        self.assertTrue(
            Parameter.objects.annotate_configured(self.user)
            .get(name="testparameter")
            .configured
        )

        pc.delete()
        param.delete()


class PluginConfigQuerySetTestCase(CustomTestCase):
    def test_visible_for_user_owner(self):
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=self.superuser,
            parameter=Parameter.objects.first(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.user)
            .count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.superuser)
            .count(),
        )
        pc.delete()

    def test_visible_for_user_default(self):
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=False,
            owner=None,
            parameter=Parameter.objects.first(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.user)
            .count(),
        )
        pc.delete()

    def test_visible_for_user_organization(self):
        pc = PluginConfig.objects.create(
            value="myperfecttest",
            for_organization=True,
            owner=self.superuser,
            parameter=Parameter.objects.first(),
        )
        self.assertEqual(
            0,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.user)
            .count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.superuser)
            .count(),
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(
            user=self.superuser, organization=org, is_owner=True
        )
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )

        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.user)
            .count(),
        )
        self.assertEqual(
            1,
            PluginConfig.objects.filter(value="myperfecttest")
            .visible_for_user(self.superuser)
            .count(),
        )

        m1.delete()
        m2.delete()
        org.delete()
        pc.delete()


class JobQuerySetTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        Job.objects.all().delete()

    def tearDown(self) -> None:
        super().tearDown()
        Job.objects.all().delete()

    def test_annotate_importance_date_this_day(self):
        Job.objects.create(
            tlp="RED",
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(hours=5),
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_date()
            .first()
        )
        self.assertEqual(3, j.date_weight)
        j.delete()

    def test_annotate_importance_date_this_week(self):
        Job.objects.create(
            tlp="RED",
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(days=5),
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_date()
            .first()
        )
        self.assertEqual(2, j.date_weight)
        j.delete()

    def test_annotate_importance_date_old(self):
        Job.objects.create(
            tlp="RED",
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            finished_analysis_time=now() - datetime.timedelta(days=30),
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_date()
            .first()
        )
        self.assertEqual(0, j.date_weight)
        j.delete()

    def test_annotate_importance_user_same_user_same_org(self):
        Job.objects.create(
            tlp="RED",
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(
            user=self.superuser, organization=org, is_owner=True
        )
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_user(self.user)
            .first()
        )
        self.assertEqual(3, j.user_weight)
        j.delete()
        m1.delete()
        m2.delete()
        org.delete()

    def test_annotate_importance_user_same_org(self):
        Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(
            user=self.superuser, organization=org, is_owner=True
        )
        m2 = Membership.objects.create(
            user=self.user,
            organization=org,
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_user(self.user)
            .first()
        )
        self.assertEqual(2, j.user_weight)
        j.delete()
        m1.delete()
        m2.delete()
        org.delete()

    def test_annotate_importance_user_valid(self):
        Job.objects.create(
            tlp="RED",
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_user(self.user)
            .first()
        )
        self.assertEqual(3, j.user_weight)
        j.delete()

    def test_annotate_importance_user_wrong(self):
        Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        j = (
            Job.objects.filter(observable_name="test.com")
            ._annotate_importance_user(self.user)
            .first()
        )
        self.assertEqual(0, j.user_weight)
        j.delete()

    def test_visible_for_user_tlp(self):
        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visible_for_user(self.user).count())
        j.delete()
        j = Job.objects.create(
            tlp="GREEN",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visible_for_user(self.superuser).count())
        self.assertEqual(1, Job.objects.visible_for_user(self.user).count())
        j.delete()

    def test_visible_for_user_membership(self):
        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
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
