from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel
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
        self.assertEqual(result["count"], 1)

    def test_get_analyzables(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            f"{self.URL}/get_analyzables",
            data=["test.com"],
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(result[0]["id"], self.an.pk)

        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            f"{self.URL}/get_analyzables",
            data=["noanalyzable.com"],
            format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(result[0]["tags"], ["not_found"])
