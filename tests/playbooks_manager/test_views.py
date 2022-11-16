from django.test import TransactionTestCase

from api_app.models import Job
from api_app.playbooks_manager.dataclasses import PlaybookConfig
from api_app.playbooks_manager.serializers import CachedPlaybooksSerializer
from api_app.playbooks_manager.views import _cache_playbook


class PlaybookViewTestCase(TransactionTestCase):

    playbook_name = ""

    def test_cache_config(self):
        job = Job.objects.first()
        planned_name = "TEST_NEW_PLAYBOOK"
        planned_description = "This is a test description"
        data = {
            "name": planned_name,
            "description": planned_description,
            "job_id": job.id,
        }
        playbook = _cache_playbook(data, CachedPlaybooksSerializer)

        self.assertEqual(planned_name, playbook.get("name"))

        self.assertEqual(planned_description, playbook.get("description"))

        self.assertNotEqual(playbook.get("supports"), [])

        self.assertEqual(
            playbook.get("default"), True
        )  # to make sure that they are actually picked up by the frontend
        self.playbook_name = playbook.get("name")

    def test_cached_playbook_presence(self):
        playbook = PlaybookConfig.get(self.playbook_name, None)
        self.assertNotEqual(playbook, None)
