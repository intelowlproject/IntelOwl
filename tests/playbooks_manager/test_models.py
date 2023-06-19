from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase


class PlaybookConfigTestCase(CustomTestCase):

    def test_ordered_for_user(self):

        pc = PlaybookConfig.objects.create(name="test", type=["ip"], description="test")
        pc.analyzers.set([AnalyzerConfig.objects.first()])
        Job.objects.create(
            user=self.user,
            observable_name="test3.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc
        )
        Job.objects.create(
            user=self.user,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc
        )
        Job.objects.create(
            user=self.superuser,
            observable_name="test2.com",
            observable_classification="domain",
            status="reported_without_fails",
            playbook_to_execute=pc
        )
        pcs = PlaybookConfig.ordered_for_user(self.user).get(name="test")
        self.assertEqual(2, pcs.user_weight)
        self.assertEqual(1, pcs.other_weight)
        self.assertEqual(7, pcs.weight)
