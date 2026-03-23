from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.models import UserDomainWildCardEvent
from api_app.user_events_manager.serializers import UserDomainWildCardEventSerializer
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class TestUserDomainWildCardEvent(CustomTestCase):
    def test_save_and_read(self):
        an = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )
        u = UserDomainWildCardEventSerializer(
            data={
                "query": ".*\.com",
                "decay_progression": 0,
                "decay_timedelta_days": 3,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(user=self.user)},
        )
        self.assertTrue(u.is_valid(), u.errors)
        res: UserDomainWildCardEvent = u.save()
        self.assertCountEqual(res.analyzables.values_list("pk", flat=True), [an.pk])
        an2 = Analyzable.objects.create(
            name="test2.com",
            classification=Classification.DOMAIN,
        )
        res.refresh_from_db()
        self.assertCountEqual(res.analyzables.values_list("pk", flat=True), [an.pk, an2.pk])

        res.delete()
        an.delete()
        an2.delete()
