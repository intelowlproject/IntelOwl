import datetime
from unittest.mock import patch

from django.db import IntegrityError, connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.models import (
    UserAnalyzableEvent,
    UserDomainWildCardEvent,
    UserIPWildCardEvent,
)
from api_app.user_events_manager.serializers import (
    UserAnalyzableEventSerializer,
    UserDomainWildCardEventSerializer,
    UserIPWildCardEventSerializer,
)
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class TestUserAnalyzableEventQuerySet(CustomTestCase):
    def test_decay_linear(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        ue = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": 0,
                "decay_timedelta_days": 0,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid()
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()
        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)
        ua.refresh_from_db()
        self.assertEqual(ua.data_model.reliability, 7)
        ua.delete()
        an.delete()

    def test_decay_bulk_queries(self):
        analyzables = []
        events = []
        for i in range(3):
            an = Analyzable.objects.create(
                name=f"test{i}.com",
                classification=Classification.DOMAIN,
            )
            analyzables.append(an)
            ue = UserAnalyzableEventSerializer(
                data={
                    "analyzable": {"name": an.name},
                    "decay_progression": 0,
                    "decay_timedelta_days": 0,
                    "data_model_content": {"evaluation": "malicious", "reliability": 8},
                },
                context={"request": MockUpRequest(self.user)},
            )
            ue.is_valid()
            ua = ue.save()
            ua.next_decay = now() - datetime.timedelta(days=1)
            ua.save()
            events.append(ua)

        with CaptureQueriesContext(connection) as queries:
            number = UserAnalyzableEvent.objects.decay()

        self.assertEqual(number, 3)
        self.assertLessEqual(len(queries), 12)

        for ua in events:
            ua.refresh_from_db()
            self.assertEqual(ua.data_model.reliability, 7)
            ua.delete()

        for an in analyzables:
            an.delete()

    def test_decay_atomicity_on_bulk_update_failure(self):
        an = Analyzable.objects.create(
            name="atomic.test.com",
            classification=Classification.DOMAIN,
        )
        ue = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": 0,
                "decay_timedelta_days": 0,
                "data_model_content": {"evaluation": "malicious", "reliability": 3},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid()
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        original_reliability = ua.data_model.reliability
        original_next_decay = ua.next_decay

        with (
            patch.object(UserAnalyzableEvent.objects, "bulk_update", side_effect=IntegrityError("fail")),
            self.assertRaises(IntegrityError),
        ):
            UserAnalyzableEvent.objects.decay()

        ua.refresh_from_db()
        self.assertEqual(ua.data_model.reliability, original_reliability)
        self.assertEqual(ua.next_decay, original_next_decay)

        ua.delete()
        an.delete()


class TestUserDomainWildCardEventQuerySet(CustomTestCase):
    def test_matches(self):
        an = Analyzable.objects.create(
            name="a.test.com",
            classification=Analyzable.CLASSIFICATIONS.DOMAIN,
        )
        res = UserDomainWildCardEvent.objects.matches(an)
        self.assertEqual(0, res.count())
        ue = UserDomainWildCardEventSerializer(
            data={
                "query": ".*\.test.com",
                "decay_progression": 0,
                "decay_timedelta_days": 0,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid()
        ua = ue.save()
        res = UserDomainWildCardEvent.objects.matches(an)
        self.assertEqual(1, res.count())
        ua.delete()
        an.delete()


class TestUserIPWildCardEventQuerySet(CustomTestCase):
    def test_matches(self):
        an = Analyzable.objects.create(
            name="1.2.3.5",
            classification=Analyzable.CLASSIFICATIONS.IP,
        )
        res = UserIPWildCardEvent.objects.matches(an)
        self.assertEqual(0, res.count())
        ue = UserIPWildCardEventSerializer(
            data={
                "network": "1.2.3.0/24",
                "decay_progression": 0,
                "decay_timedelta_days": 0,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid()
        ua = ue.save()
        res = UserIPWildCardEvent.objects.matches(an)
        self.assertEqual(1, res.count())
        ua.delete()
        an.delete()
