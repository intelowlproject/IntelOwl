import datetime

from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.choices import DecayProgressionEnum
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
                "decay_progression": DecayProgressionEnum.LINEAR.value,
                "decay_timedelta_days": 7,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 1)
        self.assertEqual(ua.data_model.reliability, 7)
        self.assertIsNotNone(ua.next_decay)

        ua.delete()
        an.delete()

    def test_decay_inverse_exponential(self):
        an = Analyzable.objects.create(
            name="test_exp.com",
            classification=Classification.DOMAIN,
        )
        ue = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": DecayProgressionEnum.INVERSE_EXPONENTIAL.value,
                "decay_timedelta_days": 2,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        past_time = now() - datetime.timedelta(days=1)
        ua.next_decay = past_time
        ua.save()

        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 1)
        self.assertEqual(ua.data_model.reliability, 7)
        # After first decay: decay_times=1, next_decay += timedelta(days=2**(1+1)) = 4 days
        expected_next_decay = past_time + datetime.timedelta(days=4)
        self.assertAlmostEqual(
            ua.next_decay.timestamp(),
            expected_next_decay.timestamp(),
            delta=1,
        )

        ua.delete()
        an.delete()

    def test_decay_fixed_excluded(self):
        an = Analyzable.objects.create(
            name="test_fixed.com",
            classification=Classification.DOMAIN,
        )
        ue = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": DecayProgressionEnum.FIXED.value,
                "decay_timedelta_days": 0,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        # Force next_decay to past (even though FIXED shouldn't normally have one)
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 0)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 0)
        self.assertEqual(ua.data_model.reliability, 8)

        ua.delete()
        an.delete()

    def test_decay_reliability_reaches_zero(self):
        an = Analyzable.objects.create(
            name="test_zero.com",
            classification=Classification.DOMAIN,
        )
        ue = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": DecayProgressionEnum.LINEAR.value,
                "decay_timedelta_days": 7,
                "data_model_content": {"evaluation": "malicious", "reliability": 1},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 1)
        self.assertEqual(ua.data_model.reliability, 0)
        self.assertIsNone(ua.next_decay)

        # Calling decay again should find 0 events (next_decay is None)
        number = ua.__class__.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 0)

        ua.delete()
        an.delete()

    def test_decay_multiple_events(self):
        analyzables = []
        events = []
        for i in range(3):
            an = Analyzable.objects.create(
                name=f"multi{i}.com",
                classification=Classification.DOMAIN,
            )
            analyzables.append(an)
            ue = UserAnalyzableEventSerializer(
                data={
                    "analyzable": {"name": an.name},
                    "decay_progression": DecayProgressionEnum.LINEAR.value,
                    "decay_timedelta_days": 7,
                    "data_model_content": {
                        "evaluation": "malicious",
                        "reliability": 5,
                    },
                },
                context={"request": MockUpRequest(self.user)},
            )
            ue.is_valid(raise_exception=True)
            ua = ue.save()
            ua.next_decay = now() - datetime.timedelta(days=1)
            ua.save()
            events.append(ua)

        number = UserAnalyzableEvent.objects.filter(pk__in=[e.pk for e in events]).decay()
        self.assertEqual(number, 3)

        for ua in events:
            ua.refresh_from_db()
            self.assertEqual(ua.decay_times, 1)
            self.assertEqual(ua.data_model.reliability, 4)
            self.assertIsNotNone(ua.next_decay)

        for ua in events:
            ua.delete()
        for an in analyzables:
            an.delete()

    def test_decay_no_events(self):
        number = UserAnalyzableEvent.objects.none().decay()
        self.assertEqual(number, 0)


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

    def test_decay_linear(self):
        an = Analyzable.objects.create(
            name="a.test.com",
            classification=Analyzable.CLASSIFICATIONS.DOMAIN,
        )
        ue = UserDomainWildCardEventSerializer(
            data={
                "query": r".*\.test.com",
                "decay_progression": DecayProgressionEnum.LINEAR.value,
                "decay_timedelta_days": 7,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        number = UserDomainWildCardEvent.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 1)
        self.assertEqual(ua.data_model.reliability, 7)
        self.assertIsNotNone(ua.next_decay)

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

    def test_decay_linear(self):
        an = Analyzable.objects.create(
            name="1.2.3.5",
            classification=Analyzable.CLASSIFICATIONS.IP,
        )
        ue = UserIPWildCardEventSerializer(
            data={
                "network": "1.2.3.0/24",
                "decay_progression": DecayProgressionEnum.LINEAR.value,
                "decay_timedelta_days": 7,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        ue.is_valid(raise_exception=True)
        ua = ue.save()
        ua.next_decay = now() - datetime.timedelta(days=1)
        ua.save()

        number = UserIPWildCardEvent.objects.filter(pk=ua.pk).decay()
        self.assertEqual(number, 1)

        ua.refresh_from_db()
        self.assertEqual(ua.decay_times, 1)
        self.assertEqual(ua.data_model.reliability, 7)
        self.assertIsNotNone(ua.next_decay)

        ua.delete()
        an.delete()
