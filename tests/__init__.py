import logging

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient


from intel_owl import settings


def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    # disable logging library
    if settings.DISABLE_LOGGING_TEST:
        logging.disable(logging.CRITICAL)

    return logger


class CustomAPITestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super(CustomTestCase, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        super(CustomTestCase, self).setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)
