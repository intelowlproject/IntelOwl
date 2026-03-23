import json

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.serializers import (
    UserAnalyzableEventSerializer,
    UserIPWildCardEventSerializer,
)
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
                "analyzable": {"name": self.an.name},
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
        # create user event
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": {"name": an.name},
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        # check duplicates are not allowed
        self.assertEqual(response.status_code, 201, response.content)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": {"name": an.name},
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 409, response.content)
        # create an user event for another user
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": {"name": an.name},
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        # create an evaluation for the same user, but for a different analyzable
        self.client.force_authenticate(user=self.user)
        an3 = Analyzable.objects.filter(name="test3.com", classification=Classification.DOMAIN)
        self.assertFalse(an3.exists())
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": {"name": "test3.com"},
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(an3.exists())
        an.delete()
        an3.delete()
        # test generic analyzables are not allowed
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "analyzable": {"name": "google.com:445"},
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_update(self):
        payload = {
            "analyzable": {"name": self.an.name},
            "data_model_content": {"evaluation": "trusted", "reliability": 10},
        }
        self.client.force_authenticate(self.user)
        response = self.client.patch(f"{self.URL}/{self.res.pk}", payload, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.client.force_authenticate(self.guest)
        response = self.client.patch(f"{self.URL}/{self.res.pk}", payload, format="json")
        self.assertEqual(response.status_code, 404, response.json())

    def test_delete(self):
        self.client.force_authenticate(self.superuser)
        # 1. owner/admin can't delete a event created by an user
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 404)
        self.client.force_authenticate(self.user)
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 204)
        response = self.client.delete(f"{self.URL}/{self.res.pk}")
        self.assertEqual(response.status_code, 404)


class TestUserIPWildCardEventViewSet(CustomViewSetTestCase):
    URL = "/api/user_event/ip_wildcard"

    def setUp(self):
        super().setUp()
        self.an = Analyzable.objects.create(
            name="1.2.3.4",
            classification=Classification.IP,
        )
        u = UserIPWildCardEventSerializer(
            data={
                "network": "1.2.3.0/24",
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

        u = UserIPWildCardEventSerializer(
            data={
                "network": "1.2.4.0/24",
                "decay_progression": 0,
                "decay_timedelta_days": 3,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(user=self.user)},
        )

        u.is_valid(raise_exception=True)
        u.save()

        response = self.client.get(self.URL + "?network=1.2.3.0/24")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertIn("count", result)
        self.assertEqual(result["count"], 1)

    def test_create(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "network": "1.2.4.0/24",
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
                    "network": "1.2.4.0/24",
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
                    "network": "1.2.3.0/24",
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_validate(self):
        self.client.force_authenticate(self.user)
        response = self.client.put(f"{self.URL}/validate", {"network": "1.2.3.0/24"}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        result = response.json()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.an.name)

        an2 = Analyzable.objects.create(
            name="1.2.4.4",
            classification=Classification.IP,
        )
        response = self.client.put(f"{self.URL}/validate", {"network": "1.2.3.0/24"}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        result = response.json()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.an.name)

        an2.delete()


class TestUserDomainWildCardEventViewSet(CustomViewSetTestCase):
    URL = "/api/user_event/domain_wildcard"

    def setUp(self):
        super().setUp()
        self.an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

    def tearDown(self):
        super().tearDown()
        self.an.delete()

    def test_create(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            self.URL,
            data=json.dumps(
                {
                    "query": ".*\.com",
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
                    "query": ".*\.com",
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
                    "query": ".*\.com",
                    "decay_progression": 0,
                    "decay_timedelta_days": 3,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)

    def test_validate(self):
        self.client.force_authenticate(self.user)
        response = self.client.put(f"{self.URL}/validate", {"query": "*\.test.com"}, format="json")
        self.assertEqual(response.status_code, 400, response.json())

        response = self.client.put(f"{self.URL}/validate", {"query": ".*\.?test.com"}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        result = response.json()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.an.name)
