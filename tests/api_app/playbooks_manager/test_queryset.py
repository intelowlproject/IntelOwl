from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.playbooks_manager.queryset import PlaybookConfigQuerySet
from authentication.models import UserProfile
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from certego_saas.apps.user.models import User
from tests import CustomTestCase


class PlaybookConfigQuerySetTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.pc = PlaybookConfig.objects.create(name="testplaybook", type=["ip"], description="test")
        self.an1 = Analyzable.objects.create(
            name="test3.com",
            classification=Classification.DOMAIN,
        )
        self.an2 = Analyzable.objects.create(
            name="test_robot.com",
            classification=Classification.DOMAIN,
        )

        self.pc.analyzers.set([AnalyzerConfig.objects.first()])
        self.j1 = Job.objects.create(
            user=self.superuser,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=self.pc,
            finished_analysis_time=now(),
        )

        self.j2 = Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=self.pc,
            finished_analysis_time=now(),
        )
        self.j3 = Job.objects.create(
            user=self.superuser,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=self.pc,
            finished_analysis_time=now(),
        )

    def tearDown(self):
        self.an1.delete()
        self.an2.delete()
        self.j1.delete()
        self.j2.delete()
        self.j3.delete()

    def test__subquery_user(self):
        subq = PlaybookConfigQuerySet._subquery_weight_user(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="testplaybook")
        self.assertEqual(1, pc.weight)

    def test__subquery_org_not_membership(self):
        subq = PlaybookConfigQuerySet._subquery_weight_org(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="testplaybook")
        self.assertEqual(0, pc.weight)

    def test__subquery_org(self):
        org = Organization.objects.create(name="test_org")

        Membership.objects.create(
            user=self.superuser,
            organization=org,
        )
        Membership.objects.create(user=self.user, organization=org, is_owner=True)
        subq = PlaybookConfigQuerySet._subquery_weight_org(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="testplaybook")
        self.assertEqual(2, pc.weight)

    def test__subquery_other(self):
        subq = PlaybookConfigQuerySet._subquery_weight_other(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="testplaybook")
        self.assertEqual(2, pc.weight)

    def test_ordered_for_user(self):
        """Check user playbooks are in the correct order and the robot jobs are excluded"""

        try:
            robot = User.objects.get(is_superuser=False, username="robot")
        except User.DoesNotExist:
            robot = User.objects.create(username="robot", email="robot@intelowl.com", password="test")
        robot_profile = UserProfile.objects.get(user=robot)
        robot_profile.is_robot = True
        robot_profile.save()

        org = Organization.objects.create(name="test_org")
        Membership.objects.create(user=self.user, organization=org, is_owner=True)
        Membership.objects.create(user=robot, organization=org)

        pc2 = PlaybookConfig.objects.create(name="second", type=["ip"], description="test")
        pc3 = PlaybookConfig.objects.create(name="third", type=["ip"], description="test")
        pc4 = PlaybookConfig.objects.create(name="fourth", type=["ip"], description="test")

        Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=self.pc,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=self.pc,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=pc3,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=self.user,
            analyzable=self.an1,
            status="reported_without_fails",
            playbook_to_execute=pc4,
            finished_analysis_time=now(),
        )
        # robot jobs
        Job.objects.create(
            user=robot,
            analyzable=self.an2,
            status="reported_without_fails",
            playbook_to_execute=pc2,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=robot,
            analyzable=self.an2,
            status="reported_without_fails",
            playbook_to_execute=pc2,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=robot,
            analyzable=self.an2,
            status="reported_without_fails",
            playbook_to_execute=pc2,
            finished_analysis_time=now(),
        )

        Job.objects.create(
            user=robot,
            analyzable=self.an2,
            status="reported_without_fails",
            playbook_to_execute=pc2,
            finished_analysis_time=now(),
        )
        Job.objects.create(
            user=robot,
            analyzable=self.an2,
            status="reported_without_fails",
            playbook_to_execute=pc2,
            finished_analysis_time=now(),
        )

        pcs = (
            PlaybookConfig.objects.ordered_for_user(self.user)
            .filter(description="test")
            .values_list("name", flat=True)
        )
        self.assertEqual(4, len(pcs))
        self.assertEqual("testplaybook", pcs[0])
        self.assertEqual("fourth", pcs[1])
        self.assertEqual("third", pcs[2])
        self.assertEqual("second", pcs[3])
