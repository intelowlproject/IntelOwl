import logging
from abc import ABCMeta, abstractmethod

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.core.models import AbstractReport
from api_app.models import Job
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
    @property
    @abstractmethod
    def report_model(self):
        """
        Returns Model to be used for *init_report*
        """
        raise NotImplementedError()

    def init_report(self, status=None):
        _job = Job.objects.create(
            status="running",
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        _report, _ = self.report_model.objects.get_or_create(
            **{
                "job_id": _job.id,
                "name": "MISP",
                "status": AbstractReport.Status.PENDING if status is None else status,
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
            }
        )
        return _report

    @property
    def plugin_name(self):
        return getattr(self.report, f"{self.plugin_type}_name")

    def test_kill_plugin_204(self):
        response = self.client.patch(
            f"/api/job/{self.report.job_id}/{self.plugin_type}/{self.plugin_name}/kill"
        )
        self.assertEqual(response.status_code, 204)
        self.report.refresh_from_db()
        self.assertEqual(self.report.status, AbstractReport.Status.KILLED)

    def test_kill_plugin_404(self):
        response = self.client.patch(
            f"/api/job/{self.report.job_id}/{self.plugin_type}/PLUGIN_404/kill"
        )
        self.assertEqual(response.status_code, 404)

    def test_kill_plugin_400(self):
        # create a new report whose status is not "running"/"pending"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS)
        response = self.client.patch(
            f"/api/job/{_report.job_id}/{self.plugin_type}/{self.plugin_name}/kill"
        )
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(
            response.json(), {"detail": "Plugin call is not running or pending"}
        )

    def test_retry_plugin_204(self):
        # create new report with status failed
        _report = self.init_report(status=AbstractReport.Status.FAILED)
        response = self.client.patch(
            f"/api/job/{_report.job_id}/{self.plugin_type}/{self.plugin_name}/retry"
        )
        self.assertEqual(response.status_code, 204)

    def test_retry_plugin_404(self):
        response = self.client.patch(
            f"/api/job/{self.report.job_id}/{self.plugin_type}/PLUGIN_404/retry"
        )
        self.assertEqual(response.status_code, 404)

    def test_retry_plugin_400(self):
        # create a new report whose status is not "failed"/"killed"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS)
        response = self.client.patch(
            f"/api/job/{_report.job_id}/{self.plugin_type}/{self.plugin_name}/retry"
        )
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(
            response.json(), {"detail": "Plugin call status should be failed or killed"}
        )
