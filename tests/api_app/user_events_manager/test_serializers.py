import datetime

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.models import UserAnalyzableEvent, UserIPWildCardEvent, UserDomainWildCardEvent
from api_app.user_events_manager.serializers import UserEventSerializer, UserAnalyzableEventSerializer, \
    UserDomainWildCardEventSerializer, UserIPWildCardEventSerializer
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class TestUserAnalyzableEventSerializer(CustomTestCase):
    def test_save_and_read(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        u = UserAnalyzableEventSerializer(data={
            "analyzable": an.pk,
            "decay_progression": 0,
            "decay_timedelta_days": 3,
            "data_model_content": {
                "evaluation": "malicious",
                "reliability": 8
            }
        }, context={"request": MockUpRequest(user=self.user)},)
        self.assertTrue(u.is_valid(), u.errors)
        res: UserAnalyzableEvent = u.save()
        self.assertEqual(0, res.decay_progression)
        self.assertEqual(3, res.decay_timedelta_days)
        self.assertEqual(an.pk, res.analyzable_id)
        self.assertIsNotNone(res.next_decay)
        self.assertEqual(res.next_decay, res.date + datetime.timedelta(days=3))
        self.assertEqual(res.data_model.evaluation, "malicious")
        self.assertEqual(res.data_model.reliability, 8)

        data = UserAnalyzableEventSerializer(res).data
        self.assertEqual(data["data_model"]["evaluation"], "malicious")
        self.assertEqual(data["data_model"]["reliability"], 8)
        self.assertEqual(data["analyzable"], an.pk)
        an.delete()
        res.delete()

class TestUserDomainWildCardEventSerializer(CustomTestCase):
    def test_save_and_read(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        u = UserDomainWildCardEventSerializer(data={
            "query":".*\.com" ,
            "decay_progression": 0,
            "decay_timedelta_days": 3,
            "data_model_content": {
                "evaluation": "malicious",
                "reliability": 8
            }
        }, context={"request": MockUpRequest(user=self.user)},)
        self.assertTrue(u.is_valid(), u.errors)
        res: UserDomainWildCardEvent = u.save()
        self.assertEqual(0, res.decay_progression)
        self.assertEqual(3, res.decay_timedelta_days)
        self.assertIn(an.pk, res.analyzables.values_list("pk", flat=True))
        self.assertIsNotNone(res.next_decay)
        self.assertEqual(res.next_decay, res.date + datetime.timedelta(days=3))
        self.assertEqual(res.data_model.evaluation, "malicious")
        self.assertEqual(res.data_model.reliability, 8)
        data = UserDomainWildCardEventSerializer(res).data
        self.assertEqual(data["data_model"]["evaluation"], "malicious")
        self.assertEqual(data["data_model"]["reliability"], 8)
        self.assertCountEqual(data["analyzables"], [an.pk])
        res.delete()
        an.delete()

class TestUserIPWildCardEventSerializer(CustomTestCase):
    def test_save_and_read(self):
        an = Analyzable.objects.create(
            name="1.2.3.4",
            classification=Classification.IP,
        )
        u = UserIPWildCardEventSerializer(data={
            "network": "1.2.3.0/24",
            "decay_progression": 0,
            "decay_timedelta_days": 3,
            "data_model_content": {
                "evaluation": "malicious",
                "reliability": 8
            }
        }, context={"request": MockUpRequest(user=self.user)},)
        self.assertTrue(u.is_valid(), u.errors)
        res: UserIPWildCardEvent = u.save()
        self.assertEqual(0, res.decay_progression)
        self.assertEqual(3, res.decay_timedelta_days)
        print(res.start_ip)
        print(res.end_ip)
        self.assertIn(an.pk, res.analyzables.values_list("pk", flat=True))
        self.assertIsNotNone(res.next_decay)
        self.assertEqual(res.next_decay, res.date + datetime.timedelta(days=3))
        self.assertEqual(res.data_model.evaluation, "malicious")
        self.assertEqual(res.data_model.reliability, 8)
        data = UserIPWildCardEventSerializer(res).data
        self.assertEqual(data["data_model"]["evaluation"], "malicious")
        self.assertEqual(data["data_model"]["reliability"], 8)
        self.assertCountEqual(data["analyzables"], [an.pk])

        res.delete()
        an.delete()