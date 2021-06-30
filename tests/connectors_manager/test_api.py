from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

import logging

from intel_owl import settings
from api_app.connectors_manager.serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)
# disable logging library
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


class ApiViewTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(ApiViewTests, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_get_connector_config(self):
        response = self.client.get("/api/get_connector_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), ConnectorConfigSerializer.read_and_verify_config()
        )
