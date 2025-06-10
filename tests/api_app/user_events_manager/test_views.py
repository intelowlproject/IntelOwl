import json

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.serializers import UserAnalyzableEventSerializer
from tests import CustomViewSetTestCase
from tests.mock_utils import MockUpRequest


class TestUserAnalyzableEventViewSet(CustomViewSetTestCase):
    URL = "/api/user_event/analyzable"

    def setUp(self):
        super().setUp()
        self.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        u = UserAnalyzableEventSerializer(
            data={
                "analyzable": self.an.pk,
                "decay_progression": 0,
                "decay_timedelta_days": 3,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(user=self.user)},
        )

        u.is_valid(raise_exception=True)
        self.res = u.save()

    def tearDown(self):
        super().tearDown()
        self.res.delete()
        self.an.delete()

    def test_list(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)

        response = self.client.get(self.URL + f"?username={self.user.username}")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)

        response = self.client.get(self.URL + f"?username={self.superuser.username}")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 0)

        response = self.client.get(self.URL + f"?analyzable_name={self.an.name}")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)

        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 0)

        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(self.URL + f"?username={self.user.username}")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 0)

    def test_create(self):
        an = Analyzable.objects.create(
            name="test2.com",
            classification=Classification.DOMAIN,
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": an.pk,
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": an.pk,
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": an.pk,
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)

        an.delete()

    def test_delete(self):
        self.client.force_authenticate(self.superuser)
        # 1. owner/admin can't delete a playbook created by an user
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(self.user)
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 204)
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 404)
