import datetime

from django.utils.timezone import now

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.models import (
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

import datetime
import time
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from api_app.user_events_manager.choices import DecayProgressionEnum
from api_app.user_events_manager.serializers import UserAnalyzableEventSerializer
from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class TestDecayPerformance(CustomTestCase):
    """
    Proves that decay() runs 2×N queries with the current implementation.
    After the bulk-UPDATE fix it should run a constant number of queries.
    """

    def _make_event(self, name):
        an = Analyzable.objects.create(name=name, classification=Classification.DOMAIN)
        s = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": DecayProgressionEnum.LINEAR.value,
                "decay_timedelta_days": 7,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(self.user)},
        )
        s.is_valid(raise_exception=True)
        ua = s.save()
        ua.next_decay = now() - datetime.timedelta(days=1)   # force it to be due
        ua.save()
        return ua, an

    def test_decay_query_count_is_constant(self):
        """
        With N = 20 events, the old loop fires 2*N = 40 UPDATE queries.
        The fixed version must stay below a constant threshold (e.g. < 10).
        """
        N = 20
        created = [self._make_event(f"bench-{i}.example.com") for i in range(N)]
        pks = [ua.pk for ua, _ in created]

        with CaptureQueriesContext(connection) as ctx:
            count = created[0][0].__class__.objects.filter(pk__in=pks).decay()

        query_count = len(ctx.captured_queries)
        print(f"\n[BENCHMARK] N={N} events → {query_count} SQL queries")
        # Uncomment next line BEFORE the fix to capture the failure output as proof:
        # self.fail(f"Current implementation uses {query_count} queries for N={N}")

        # After the fix, assert it's O(1):
        self.assertEqual(count, N)
        self.assertLess(query_count, 10,
            f"decay() ran {query_count} queries for N={N}; expected O(1), got O(N).")

        for ua, an in created:
            ua.delete()
            an.delete()

    def test_decay_wall_time_scales_linearly(self):
        """
        Times decay() for N=10 vs N=50. With the loop, time ≈ 5×.
        After the fix, both should be nearly equal (O(1) SQL).
        """
        def run_decay(n):
            created = [self._make_event(f"time-{n}-{i}.example.com") for i in range(n)]
            pks = [ua.pk for ua, _ in created]
            start = time.perf_counter()
            created[0][0].__class__.objects.filter(pk__in=pks).decay()
            elapsed = time.perf_counter() - start
            for ua, an in created:
                ua.delete()
                an.delete()
            return elapsed

        t_small = run_decay(10)
        t_large = run_decay(50)
        ratio = t_large / t_small
        print(f"\n[BENCHMARK] N=10 → {t_small:.3f}s | N=50 → {t_large:.3f}s | ratio={ratio:.1f}×")
        # With the old loop, ratio ≈ 5. With bulk UPDATE, ratio ≈ 1.
        self.assertLess(ratio, 3.0,
            f"decay() time scaled {ratio:.1f}× when N grew 5×; expected near-constant time.")

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
