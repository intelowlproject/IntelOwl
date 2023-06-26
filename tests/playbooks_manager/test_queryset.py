from django.utils.timezone import now

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.playbooks_manager.queryset import PlaybookConfigQuerySet
from certego_saas.apps.organization.membership import Membership
from certego_saas.apps.organization.organization import Organization
from tests import CustomTestCase


class PlaybookConfigQuerySetTestCase(CustomTestCase):
    def test__subquery_user(self):
        pc = PlaybookConfig.objects.create(name="test", type=["ip"], description="test")
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        j1 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j2 = Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j3 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        subq = PlaybookConfigQuerySet._subquery_user(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="test")
        self.assertEqual(1, pc.weight)
        j1.delete()
        j2.delete()
        j3.delete()
        pc.delete()

    def test__subquery_org_not_membership(self):
        pc = PlaybookConfig.objects.create(name="test", type=["ip"], description="test")
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        j1 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )

        j2 = Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j3 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        subq = PlaybookConfigQuerySet._subquery_org(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="test")
        self.assertEqual(0, pc.weight)

        j1.delete()
        j2.delete()
        j3.delete()
        pc.delete()

    def test__subquery_org(self):
        pc = PlaybookConfig.objects.create(name="test", type=["ip"], description="test")
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        j1 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )

        j2 = Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j3 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        org = Organization.objects.create(name="test_org")

        m1 = Membership.objects.create(
            user=self.superuser,
            organization=org,
        )
        m2 = Membership.objects.create(user=self.user, organization=org, is_owner=True)
        subq = PlaybookConfigQuerySet._subquery_org(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="test")
        self.assertEqual(2, pc.weight)

        m1.delete()
        m2.delete()
        org.delete()
        j1.delete()
        j2.delete()
        j3.delete()
        pc.delete()

    def test__subquery_other(self):
        pc = PlaybookConfig.objects.create(name="test", type=["ip"], description="test")
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        j1 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j2 = Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        j3 = Job.objects.create(
            user=self.superuser,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )
        subq = PlaybookConfigQuerySet._subquery_other(self.user)
        pc = PlaybookConfig.objects.annotate(weight=subq).get(name="test")
        self.assertEqual(2, pc.weight)
        j1.delete()
        j2.delete()
        j3.delete()
        pc.delete()

    def test_ordered_for_user(self):
        pc2 = PlaybookConfig.objects.create(
            name="third", type=["ip"], description="test"
        )
        pc3 = PlaybookConfig.objects.create(
            name="second", type=["ip"], description="test"
        )
        pc = PlaybookConfig.objects.create(
            name="zz_first", type=["ip"], description="test"
        )
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        j1 = Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc,
            finished_analysis_time=now(),
        )

        pcs = (
            PlaybookConfig.objects.ordered_for_user(self.user)
            .filter(description="test")
            .values_list("name", flat=True)
        )
        self.assertEqual(3, len(pcs))
        self.assertEqual("zz_first", pcs[0])
        self.assertEqual("second", pcs[1])
        self.assertEqual("third", pcs[2])
        pc.delete()
        pc2.delete()
        pc3.delete()
        j1.delete()
