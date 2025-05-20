from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel, FileDataModel
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomViewSetTestCase


class TestAnalyzablesViewSet(CustomViewSetTestCase):
    URL = "/api/analyzable"

    def setUp(self):
        super().setUp()
        self.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        self.domain_data_model = DomainDataModel.objects.create()
        self.job = Job.objects.create(
            analyzable=self.an,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            data_model=self.domain_data_model,
            playbook_to_execute=PlaybookConfig.objects.first(),
            user=self.user,
        )

        self.an2 = Analyzable.objects.create(
            name="f9bc35a57b22f82c94dbcc420f71b903",
            classification=Classification.HASH,
        )
        self.domain_data_model2 = FileDataModel.objects.create()
        self.job2 = Job.objects.create(
            analyzable=self.an2,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            data_model=self.domain_data_model2,
            playbook_to_execute=PlaybookConfig.objects.first(),
            user=self.user,
        )

    def tearDown(self):
        super().tearDown()
        self.an.delete()
        self.domain_data_model.delete()
        self.job.delete()

    def test_list(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 2)

        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}?name=test.com")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["name"], "test.com")

        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}?name=google.com")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 0)

        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}?name=test.com&name=google.com")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["name"], "test.com")

        self.client.force_authenticate(user=self.user)
        response = self.client.get(
            f"{self.URL}?name=test.com&name=f9bc35a57b22f82c94dbcc420f71b903"
        )
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            result["results"][0]["name"], "f9bc35a57b22f82c94dbcc420f71b903"
        )
        self.assertEqual(result["results"][1]["name"], "test.com")
