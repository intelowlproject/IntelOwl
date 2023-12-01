from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase


class CreateJobsFromPlaybookInterfaceTestCase(CustomTestCase):
    class Test(CreateJobsFromPlaybookInterface):
        def __init__(self, playbook: PlaybookConfig):
            self.playbook_to_execute = playbook
            self.playbook_to_execute_id = self.playbook_to_execute.pk
            self.name = "Test"

    def test_validate_playbook_to_execute(self):
        default_pc = PlaybookConfig.objects.create(
            name="Playbook", type=["ip"], description="test"
        )
        a = self.Test(default_pc)
        try:
            a.validate_playbook_to_execute(self.user)
        except RuntimeError as e:
            self.fail(e)
        default_pc.delete()
        pc_owned = PlaybookConfig.objects.create(
            name="Playbook", type=["ip"], description="test", owner=self.user
        )
        a = self.Test(pc_owned)
        try:
            a.validate_playbook_to_execute(self.user)
        except RuntimeError as e:
            self.fail(e)

        pc_owned.delete()

        pc_not_owned = PlaybookConfig.objects.create(
            name="Playbook", type=["ip"], description="test", owner=self.superuser
        )
        a = self.Test(pc_not_owned)
        with self.assertRaises(RuntimeError):
            a.validate_playbook_to_execute(self.user)
        pc_not_owned.delete()
