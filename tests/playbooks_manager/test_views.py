# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomAPITestCase


class PlaybookViewTestCase(CustomAPITestCase):

    URL = "/api/playbook"

    def test_list(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], PlaybookConfig.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        playbook = PlaybookConfig.objects.order_by("?").first()
        self.assertIsNotNone(playbook)
        playbook = playbook.name
        response = self.client.get(f"{self.URL}/{playbook}")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{playbook}")
        self.assertEqual(response.status_code, 401)

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{playbook}")
        self.assertEqual(response.status_code, 200)

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404)

    def test_create(self):
        ac, _ = AnalyzerConfig.objects.get_or_create(
            name="test",
            python_module="yara.Yara",
            description="test",
            disabled=False,
            config={"soft_time_limit": 100, "queue": "default"},
            type="observable",
            observable_supported=["ip"],
        )
        job, _ = Job.objects.get_or_create(
            user=self.user,
            runtime_configuration={
                "analyzers": {"test": {"abc": 3}},
                "connectors": {},
                "visualizers": {},
            },
        )
        job.analyzers_requested.set([ac.name])
        job.analyzers_to_execute.set([ac.name])
        response = self.client.post(
            self.URL,
            data={
                "name": "TestCreate",
                "description": "test",
                "job": job.pk,
            },
        )
        self.assertEqual(response.status_code, 201, response.json())
        try:
            pc = PlaybookConfig.objects.get(name="TestCreate")
        except PlaybookConfig.DoesNotExist as e:
            self.fail(e)
        else:
            self.assertEqual(
                pc.runtime_configuration,
                {
                    "analyzers": {"test": {"abc": 3}},
                    "connectors": {},
                    "visualizers": {},
                },
            )
            pc.delete()
        finally:
            ac.delete()
            job.delete()

    def test_update(self):
        playbook = PlaybookConfig.objects.create(
            name="Test", type=["ip"], description="test"
        )
        self.assertIsNotNone(playbook)
        response = self.client.patch(f"{self.URL}/{playbook.name}")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{playbook.name}")
        self.assertEqual(response.status_code, 200)
        playbook.delete()

    def test_delete(self):
        playbook, _ = PlaybookConfig.objects.get_or_create(
            name="Test", type=["ip"], description="test"
        )
        response = self.client.delete(f"{self.URL}/{playbook.name}")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{playbook.name}")
        self.assertEqual(response.status_code, 204)
        playbook.delete()
