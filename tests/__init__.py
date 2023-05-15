import logging
from abc import ABCMeta, abstractmethod

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from api_app.core.models import AbstractReport

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
                username="user", email="test2@intelowl.com", password="test"
            )

        try:
            cls.superuser = User.objects.get(
                is_superuser=True, username="superuser@intelowl.org"
            )
        except User.DoesNotExist:
            cls.superuser = User.objects.create_superuser(
                username="superuser@intelowl.org",
                email="test@intelowl.com",
                password="test",
            )


class CustomAPITestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
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

    @abstractmethod
    def init_report(self, status, user):
        raise NotImplementedError()

    def test_kill_204(self):
        _report = self.init_report(status=AbstractReport.Status.PENDING, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/kill"
        )
        _report.refresh_from_db()

        self.assertEqual(response.status_code, 204)
        self.assertEqual(_report.status, AbstractReport.Status.KILLED)

    def test_kill_400(self):
        # create a new report whose status is not "running"/"pending"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/kill"
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
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/kill"
        )

        self.assertEqual(response.status_code, 403)

    def test_kill_404(self):
        response = self.client.patch(f"/api/jobs/999/{self.plugin_type}/999/kill")

        self.assertEqual(response.status_code, 404)

    def test_retry_204(self):
        from api_app.models import PluginConfig

        # create new report with status "FAILED"
        _report = self.init_report(
            status=AbstractReport.Status.FAILED, user=self.superuser
        )
        self.client.force_authenticate(self.superuser)
        pcs = []
        for param in _report.config.parameters.filter(required=True):
            if "url" in param.name:
                value = "https://intelowl"
            else:
                value = "test"
            pcs.append(
                PluginConfig.objects.create(
                    value=value, parameter=param, for_organization=False, owner=None
                )
            )
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/retry"
        )

        self.assertEqual(response.status_code, 204)
        self.client.force_authenticate(self.user)
        for pc in pcs:
            pc.delete()

    def test_retry_400(self):
        # create a new report whose status is not "FAILED"/"KILLED"
        _report = self.init_report(status=AbstractReport.Status.SUCCESS, user=self.user)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/retry"
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
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/retry"
        )

        self.assertEqual(response.status_code, 403)

    def test_retry_404(self):
        response = self.client.patch(f"/api/jobs/999/{self.plugin_type}/999/retry")

        self.assertEqual(response.status_code, 404)
