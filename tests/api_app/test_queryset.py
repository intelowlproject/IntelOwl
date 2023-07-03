from api_app.models import Job, Parameter, PluginConfig
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


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

    def test_visible_for_user_tlp(self):
        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visble_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visble_for_user(self.user).count())
        j.delete()
        j = Job.objects.create(
            tlp="GREEN",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visble_for_user(self.superuser).count())
        self.assertEqual(1, Job.objects.visble_for_user(self.user).count())
        j.delete()

    def test_visible_for_user_membership(self):
        j = Job.objects.create(
            tlp="RED",
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.assertEqual(1, Job.objects.visble_for_user(self.superuser).count())
        self.assertEqual(0, Job.objects.visble_for_user(self.user).count())
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        m2 = Membership.objects.create(
            user=self.superuser,
            organization=org,
        )
        self.assertEqual(1, Job.objects.visble_for_user(self.superuser).count())
        self.assertEqual(1, Job.objects.visble_for_user(self.user).count())

        m1.delete()
        m2.delete()
        org.delete()
        j.delete()
