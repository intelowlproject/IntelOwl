from abc import ABCMeta, abstractmethod
from api_app.core.models import AbstractReport
import logging

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient


from intel_owl import settings


def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    # DISABLE_LOGGING_TEST to True -> logging disabled
    if settings.DISABLE_LOGGING_TEST:
        logging.disable(logging.CRITICAL)

    return logger


class CustomAPITestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        super(CustomAPITestCase, cls).setUpClass()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )

    def setUp(self):
        super(CustomAPITestCase, self).setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)


class PluginActionViewsetTestCase(metaclass=ABCMeta):
    @abstractmethod
    def init_report(self, status):
        """
        returns report object
        """
        raise NotImplementedError()

    @property
    def plugin_name(self):
        return getattr(self.report, f"{self.plugin_type}_name")

    def test_kill_plugin_200(self):
        response = self.client.patch(
            f"/api/job/{self.report.job_id}/{self.plugin_type}/{self.plugin_name}/kill"
        )
        self.assertEqual(response.status_code, 200)
        self.report.refresh_from_db()
        self.assertEqual(self.report.status, AbstractReport.Statuses.KILLED.name)

    def test_kill_plugin_404(self):
        response = self.client.patch(
            f"/api/job/{self.report.job_id}/{self.plugin_type}/PLUGIN_404/kill"
        )
        self.assertEqual(response.status_code, 404)

    def test_kill_plugin_400(self):
        # create a new report whose status is not "running"/"pending"
        _report = self.init_report(status=AbstractReport.Statuses.SUCCESS.name)
        response = self.client.patch(
            f"/api/job/{_report.job_id}/{self.plugin_type}/{self.plugin_name}/kill"
        )
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(
            response.json(), {"detail": "Plugin call is not running or pending"}
        )
