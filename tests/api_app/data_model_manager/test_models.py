from api_app.data_model_manager.models import IPDataModel
from tests import CustomTestCase


class BaseDataModelTestCase(CustomTestCase):

    def test_serialize(self):
        ip = IPDataModel.objects.create()
        results = IPDataModel.objects.filter(pk=ip.pk).serialize()
        self.assertEqual(1, len(results))
