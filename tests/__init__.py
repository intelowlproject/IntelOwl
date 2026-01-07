import logging
from abc import ABCMeta, abstractmethod
from typing import Type

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files import File
from django.db import connections
from django.db.models import Model
from django.test import TestCase
from rest_framework.test import APIClient

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification
from api_app.decorators import abstractclassproperty
from api_app.models import AbstractReport, Job

User = get_user_model()


def get_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    # DISABLE_LOGGING_TEST to True -> logging disabled
    if settings.DISABLE_LOGGING_TEST:
        logging.disable(logging.CRITICAL)

    return logger


class CustomTestCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        settings.DEBUG = True

    def tearDown(self):
        super().tearDown()
        Analyzable.objects.all().delete()

    def _create_job_from_file(self, sample, mimetype, analyzer_config) -> Job:
        try:
            with open(sample, "rb") as f:
                analyzable = Analyzable.objects.create(
                    name=sample,
                    mimetype=mimetype,
                    classification=Classification.FILE,
                    file=File(f),
                )
                _job = Job.objects.create(
                    analyzable=analyzable,
                    user=self.superuser,
                )
                _job.analyzers_to_execute.set([analyzer_config])
                return _job
        except Exception as e:
            print(f"Error: {e}")

    def _analyze_sample(
        self, sample_name, sample_md5, sample_mimetype, analyzer_name, analyzer_class
    ):
        analyzer_config = AnalyzerConfig.objects.get(name=analyzer_name)
        analyzer = analyzer_class(analyzer_config)
        analyzer.md5 = sample_md5
        analyzer.filename = f"test_files/{sample_name}"
        analyzer.file_mimetype = sample_mimetype
        job = self._create_job_from_file(
            f"test_files/{sample_name}", sample_mimetype, analyzer_config
        )
        analyzer.start(job.id, {}, 1)
        return analyzer.report.report

    @classmethod
    def setUpTestData(cls):
        try:
            cls.guest = User.objects.get(is_superuser=False, username="guest")
        except User.DoesNotExist:
            cls.guest = User.objects.create(
                username="guest", email="guest@intelowl.com", password="test"
            )

        try:
            cls.user = User.objects.get(is_superuser=False, username="user")
        except User.DoesNotExist:
            cls.user = User.objects.create(
                username="user", email="user@intelowl.com", password="test"
            )

        try:
            cls.admin = User.objects.get(is_superuser=False, username="admin")
        except User.DoesNotExist:
            cls.admin = User.objects.create(
                username="admin", email="admin@intelowl.com", password="test"
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

    @staticmethod
    def query_count_all() -> int:
        return sum(len(c.queries) for c in connections.all())


class CustomViewSetTestCase(CustomTestCase):
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

    def tearDown(self):
        super().tearDown()
        Job.objects.all().delete()
        Analyzable.objects.all().delete()

    @abstractmethod
    def init_report(self, status, user):
        raise NotImplementedError()

    def test_kill_204(self):
        _report = self.init_report(
            status=AbstractReport.STATUSES.PENDING, user=self.user
        )
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/kill"
        )
        _report.refresh_from_db()

        self.assertEqual(response.status_code, 204)
        self.assertEqual(_report.status, AbstractReport.STATUSES.KILLED)

    def test_kill_400(self):
        # create a new report whose status is not "running"/"pending"
        _report = self.init_report(
            status=AbstractReport.STATUSES.SUCCESS, user=self.user
        )
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/kill"
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"],
            {"detail": "Plugin is not running or pending"},
            msg=msg,
        )

    def test_kill_403(self):
        # create a new report which does not belong to user
        _report = self.init_report(status=AbstractReport.STATUSES.PENDING, user=None)
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
            status=AbstractReport.STATUSES.FAILED, user=self.superuser
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
                    value=value,
                    parameter=param,
                    for_organization=False,
                    owner=None,
                    **{_report.config.snake_case_name: _report.config},
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
        _report = self.init_report(
            status=AbstractReport.STATUSES.SUCCESS, user=self.user
        )
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/retry"
        )
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"],
            {"detail": "Plugin status should be failed or killed"},
            msg=msg,
        )

    def test_retry_403(self):
        # create a new report which does not belong to user
        _report = self.init_report(status=AbstractReport.STATUSES.FAILED, user=None)
        response = self.client.patch(
            f"/api/jobs/{_report.job_id}/{self.plugin_type}/{_report.pk}/retry"
        )

        self.assertEqual(response.status_code, 403)

    def test_retry_404(self):
        response = self.client.patch(f"/api/jobs/999/{self.plugin_type}/999/retry")

        self.assertEqual(response.status_code, 404)


class ViewSetTestCaseMixin:
    @abstractclassproperty
    def model_class(cls) -> Type[Model]:
        raise NotImplementedError()

    def test_list(self):
        response = self.client.get(self.URL)
        result = response.json()
        self.assertEqual(response.status_code, 200, result)
        self.assertIn("count", result)
        self.assertEqual(result["count"], self.model_class.objects.all().count())
        self.assertIn("results", result)
        self.assertTrue(isinstance(result["results"], list))

        self.client.force_authenticate(None)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 401, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.json())

    def test_get_user(self):
        plugin = self.get_object()
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def test_get_guest(self):
        self.client.force_authenticate(self.user)
        plugin = self.get_object()
        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 401, response.json())

    def test_get_superuser(self):
        plugin = self.get_object()
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def test_get_non_existent(self):
        response = self.client.get(f"{self.URL}/NON_EXISTENT")
        self.assertEqual(response.status_code, 404, response.json())

    def get_object(self):
        return self.model_class.objects.order_by("?").first().name

    def test_update(self):
        plugin = self.get_object()
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.patch(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())

    def test_delete(self):
        plugin = self.get_object()
        response = self.client.delete(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())
        self.client.force_authenticate(self.superuser)
        response = self.client.delete(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 405, response.json())

    def test_create(self):
        response = self.client.post(self.URL)
        self.assertEqual(response.status_code, 405, response.json())
