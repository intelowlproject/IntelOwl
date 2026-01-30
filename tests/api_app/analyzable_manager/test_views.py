import datetime
from unittest.mock import patch

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel, FileDataModel
from api_app.investigations_manager.models import Investigation
from api_app.models import Job
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.user_events_manager.models import UserAnalyzableEvent
from tests import CustomViewSetTestCase


@patch(
    "api_app.analyzables_manager.views.timezone.now",
    return_value=datetime.datetime(2025, 1, 2, tzinfo=datetime.timezone.utc),
)
@patch(
    "api_app.investigations_manager.models.now",
    return_value=datetime.datetime(2025, 1, 2, tzinfo=datetime.timezone.utc),
)
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
            finished_analysis_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
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
            finished_analysis_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            user=self.user,
        )

        self.an3 = Analyzable.objects.create(
            name="1.1.1.1:443",
            classification=Classification.GENERIC,
        )
        self.domain_data_model3 = DomainDataModel.objects.create(evaluation="malicious", reliability=10)
        self.job3 = Job.objects.create(
            analyzable=self.an3,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            data_model=self.domain_data_model3,
            playbook_to_execute=PlaybookConfig.objects.first(),
            finished_analysis_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            user=self.user,
        )
        self.job3.add_child(
            user=self.user,
            analyzable=self.an,
            playbook_to_execute=PlaybookConfig.objects.get(name="Dns"),
            finished_analysis_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            tlp=Job.TLP.AMBER.value,
        )  # check similar investigation works with children
        self.domain_data_model31 = DomainDataModel.objects.create(evaluation="malicious", reliability=10)
        self.uae3 = UserAnalyzableEvent.objects.create(
            analyzable=self.an3, data_model=self.domain_data_model31, user=self.user
        )
        self.investigation, _ = Investigation.objects.get_or_create(
            name="test_investigation",
            owner=self.superuser,
            start_time=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
        )
        self.investigation.jobs.add(self.job3)

    def tearDown(self):
        super().tearDown()
        self.an.delete()
        self.domain_data_model.delete()
        self.job.delete()
        self.an2.delete()
        self.domain_data_model2.delete()
        self.job2.delete()
        self.an3.delete()
        self.job3.delete()
        self.uae3.delete()
        self.investigation.delete()

    def test_list(self, *args, **kwargs):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 3)

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
        response = self.client.get(f"{self.URL}?name=test.com&name=f9bc35a57b22f82c94dbcc420f71b903")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["results"][1]["name"], "f9bc35a57b22f82c94dbcc420f71b903")
        self.assertEqual(result["results"][0]["name"], "test.com")

    def test_get(self, *args, **kwargs):
        # check generic is returned without the wrong data model
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/{self.an3.pk}")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(result["name"], self.an3.name)
        self.assertNotIn("last_data_model", result)

    def test_related_investigation_number(self, *args, **kwargs):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/{self.an.pk}/related_investigation_number")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(result["related_investigation_number"], 1)

    def test_history(self, *args, **kwargs):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.URL}/{self.an.pk}/history")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("jobs", result)
        self.assertEqual(len(result["jobs"]), 2)
        self.assertIn("user_events", result)
        self.assertIn("user_domain_wildcard_events", result)
        self.assertIn("user_ip_wildcard_events", result)
        # generic request
        generic_response = self.client.get(f"{self.URL}/{self.an3.pk}/history")
        self.assertEqual(generic_response.status_code, 200, generic_response.content)
        generic_result = generic_response.json()
        self.assertEqual(len(generic_result["jobs"]), 1)
        self.assertNotEqual(generic_result["jobs"][0]["data_model"], {})
        self.assertEqual(len(generic_result["user_events"]), 1)
        self.assertNotEqual(generic_result["user_events"][0]["data_model"], {})
        self.assertEqual(len(generic_result["user_domain_wildcard_events"]), 0)
        self.assertEqual(len(generic_result["user_ip_wildcard_events"]), 0)
