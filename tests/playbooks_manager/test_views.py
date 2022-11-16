from django.conf import settings
from django.test import TransactionTestCase

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.playbooks_manager.dataclasses import PlaybookConfig
from api_app.playbooks_manager.serializers import CachedPlaybooksSerializer
from api_app.playbooks_manager.views import _cache_playbook
from api_app.serializers import ObservableAnalysisSerializer


class PlaybookViewTestCase(TransactionTestCase):
    def setUp(self):
        self.analyzer_serializer_class = ObservableAnalysisSerializer
        self.superuser = settings.AUTH_USER_MODEL.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

        analyzers_used = ["Classic_DNS"]
        data = {
            "observables": [
                ["url", "google.com"],
            ],
            "analyzers_requested": analyzers_used,
            "connectors_requested": [],
            "tlp": "WHITE",
            "runtime_configuration": {},
            "tags_labels": [],
        }

        self.supports = ["ip", "domain", "url"]

        serializer = self.serializer_class(data=data, many=True)
        serializer.is_valid(raise_exception=True)

        serialized_data = serializer.validated_data
        [data.pop("runtime_configuration", {}) for data in serialized_data]

        self.test_jobs = serializer.save(
            user=self.superuser,
        )

    def test_cache_config(self):
        AnalyzerConfigSerializer
        job = self.test_job
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

        self.assertListEqual(playbook.get("supports"), self.supports)

        self.assertEqual(
            playbook.get("default"), True
        )  # to make sure that they are actually picked up by the frontend
        self.playbook_name = playbook.get("name")

    def test_cached_playbook_presence(self):
        playbook = PlaybookConfig.get(self.playbook_name, None)
        self.assertNotEqual(playbook, None)
