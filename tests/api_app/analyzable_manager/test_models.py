from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.serializers import (
    UserAnalyzableEventSerializer,
    UserDomainWildCardEventSerializer,
)
from tests import CustomTestCase
from tests.mock_utils import MockUpRequest


class TestAnalyzable(CustomTestCase):
    def test_get_all_user_events_data_model(self):
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
        u.is_valid()
        res = u.save()
        self.assertCountEqual(an.get_all_user_events_data_model(), [res.data_model])
        self.assertCountEqual(an.get_all_user_events_data_model(self.user), [res.data_model])
        self.assertCountEqual(an.get_all_user_events_data_model(self.superuser), [])

        u2 = UserAnalyzableEventSerializer(
            data={
                "analyzable": {"name": an.name},
                "decay_progression": 0,
                "decay_timedelta_days": 3,
                "data_model_content": {"evaluation": "malicious", "reliability": 8},
            },
            context={"request": MockUpRequest(user=self.user)},
        )
        u2.is_valid()
        res2 = u2.save()

        self.assertCountEqual(an.get_all_user_events_data_model(), [res.data_model, res2.data_model])
        self.assertCountEqual(
            an.get_all_user_events_data_model(self.user),
            [res.data_model, res2.data_model],
        )
        self.assertCountEqual(an.get_all_user_events_data_model(self.superuser), [])

        res.delete()
        res2.delete()

        an.delete()
