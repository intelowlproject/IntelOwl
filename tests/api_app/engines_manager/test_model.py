from botocore.exceptions import ValidationError

from api_app.engines_manager.models import EngineConfig
from tests import CustomTestCase


class EngineConfigTestCase(CustomTestCase):

    def test_create_multiple_config(self):
        config = EngineConfig.objects.create(modules=["evaluation.EvaluationEngineModule"])
        with self.assertRaises(Exception):
            EngineConfig.objects.create()
        config.delete()

    def test_clean(self):
        config = EngineConfig.objects.create(modules=["evaluation.EvaluationEngineModule"])
        config.modules.append("test.Test")
        with self.assertRaises(Exception):
            config.save()
        config.delete()
