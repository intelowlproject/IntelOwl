import logging
from abc import ABCMeta, abstractmethod

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.core.models import AbstractReport
from api_app.models import Job

User = get_user_model()


def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    # DISABLE_LOGGING_TEST to True -> logging disabled
    if settings.DISABLE_LOGGING_TEST:
        logging.disable(logging.CRITICAL)

    return logger


class CustomTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        try:
            cls.user = User.objects.get(is_superuser=False)
        except User.DoesNotExist:
            cls.user = User.objects.create(
                username="testUser", email="test2@intelowl.com", password="test"
            )

        try:
            cls.superuser = User.objects.get(is_superuser=True)
        except User.DoesNotExist:
            print("creating superuser")
            cls.superuser = User.objects.create_superuser(
                username="test", email="test@intelowl.com", password="test"
            )


class CustomAPITestCase(CustomTestCase):
    def setUp(self):
        super(CustomAPITestCase, self).setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)


class PluginActionViewsetTestCase(metaclass=ABCMeta):
    @property
    @abstractmethod
    def plugin_type(self):
        """
        plugin type
        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def report_model(self):
        """
        Returns model to be used for *init_report*
        """
        raise NotImplementedError()

    def init_report(self, status: str, user: User) -> AbstractReport:
        _job = Job.objects.create(
            user=user,
            status=Job.Status.RUNNING,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        _report, _ = self.report_model.objects.get_or_create(
            **{
                "job_id": _job.id,
                "status": status,
                "name": "MISP",  # analyzer and connector both exists for this name
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
            }
        )
        return _report

    def test_kill_204(self):
        _report = self.init_report(status=AbstractReport.Status.PENDING, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/kill"
        )
        _report.refresh_from_db()

        self.assertEqual(response.status_code, 204)
        self.assertEqual(_report.status, AbstractReport.Status.KILLED)

    def test_kill_400(self):
        # create a new report whose status is not "running"/"pending"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/kill"
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"],
            {"detail": "Plugin call is not running or pending"},
            msg=msg,
        )

    def test_kill_403(self):
        # create a new report which does not belong to user
        _report = self.init_report(status=AbstractReport.Status.PENDING, user=None)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/kill"
        )

        self.assertEqual(response.status_code, 403)

    def test_kill_404(self):
        response = self.client.patch(
            f"/api/jobs/999/{self.plugin_type}/PLUGIN_404/kill"
        )

        self.assertEqual(response.status_code, 404)

    def test_retry_204(self):
        # create new report with status "FAILED"
        _report = self.init_report(
            status=AbstractReport.Status.FAILED, user=self.superuser
        )
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/retry"
        )

        self.assertEqual(response.status_code, 204)
        self.client.force_authenticate(self.user)

    def test_retry_400(self):
        # create a new report whose status is not "FAILED"/"KILLED"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/retry"
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"],
            {"detail": "Plugin call status should be failed or killed"},
            msg=msg,
        )

    def test_retry_403(self):
        # create a new report which does not belong to user
        _report = self.init_report(status=AbstractReport.Status.FAILED, user=None)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.name}/retry"
        )

        self.assertEqual(response.status_code, 403)

    def test_retry_404(self):
        response = self.client.patch(
            f"/api/jobs/999/{self.plugin_type}/PLUGIN_404/retry"
        )

        self.assertEqual(response.status_code, 404)
