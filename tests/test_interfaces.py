from django.db.models import QuerySet
from api_app.interfaces import CreateJobsFromPlaybookInterface
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomTestCase

class CreateJobsFromPlaybookInterfaceTestCase(CustomTestCase):
    class TestInterface(CreateJobsFromPlaybookInterface):
        """Test implementation of CreateJobsFromPlaybookInterface."""
        def __init__(self, playbooks: QuerySet):
            self.playbooks_choice = playbooks
            self.name = "Test"

    def test_validate_playbooks(self):
        """Test the validate_playbooks method under different ownership scenarios."""
        def create_and_test_playbook(owner=None):
            playbook = PlaybookConfig.objects.create(
                name="Playbook", type=["ip"], description="test", owner=owner
            )
            interface = self.TestInterface(PlaybookConfig.objects.filter(pk=playbook.pk))
            
            if owner is None or owner == self.user:
                interface.validate_playbooks(self.user)  # Should not raise an exception
            else:
                with self.assertRaises(RuntimeError):
                    interface.validate_playbooks(self.user)
            
            playbook.delete()

        create_and_test_playbook()  # Test with no owner
        create_and_test_playbook(self.user)  # Test with current user as owner
        create_and_test_playbook(self.superuser)  # Test with different user as owner
