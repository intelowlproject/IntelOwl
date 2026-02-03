from django.db.models import QuerySet

from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase


class CreateJobsFromPlaybookInterfaceTestCase(CustomTestCase):
    class Test(CreateJobsFromPlaybookInterface):
        def __init__(self, playbooks: QuerySet):
            self.playbooks_choice = playbooks
            self.name = "Test"

    def test_validate_playbook_to_execute(self):
        default_pc = PlaybookConfig.objects.create(name="Playbook", type=["ip"], description="test")
        a = self.Test(PlaybookConfig.objects.filter(pk=default_pc.pk))
        try:
            a.validate_playbooks(self.user)
        except RuntimeError as e:
            self.fail(e)
        default_pc.delete()
        pc_owned = PlaybookConfig.objects.create(
            name="Playbook", type=["ip"], description="test", owner=self.user
        )
        a = self.Test(PlaybookConfig.objects.filter(pk=pc_owned.pk))
        try:
            a.validate_playbooks(self.user)
        except RuntimeError as e:
            self.fail(e)

        pc_owned.delete()

        pc_not_owned = PlaybookConfig.objects.create(
            name="Playbook", type=["ip"], description="test", owner=self.superuser
        )
        a = self.Test(PlaybookConfig.objects.filter(pk=pc_not_owned.pk))
        with self.assertRaises(RuntimeError):
            a.validate_playbooks(self.user)
        pc_not_owned.delete()
