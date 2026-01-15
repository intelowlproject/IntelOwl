from typing import Type

from django.db.models import Model
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.data_model_manager.models import (
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)
from api_app.decorators import classproperty
from api_app.models import Job
from tests import CustomViewSetTestCase, ViewSetTestCaseMixin


def create_report(user):
    an1, _ = Analyzable.objects.get_or_create(
        name="test.com",
        classification=Classification.DOMAIN,
    )

    job = Job.objects.create(
        analyzable=an1,
        status=Job.STATUSES.CONNECTORS_RUNNING.value,
        user=user,
    )
    return AnalyzerReport.objects.create(
        report={},
        job=job,
        config=AnalyzerConfig.objects.first(),
        status=AnalyzerReport.STATUSES.FAILED.value,
        task_id=str(uuid()),
        parameters={},
    )


class DomainDataModelViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/data_model/domain"

    def test_url(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, 200, response.content)
        try:
            response.json()
        except Exception as e:
            self.fail(e)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        report = create_report(cls.user)
        report.data_model = cls.model_class.objects.create()
        report.save()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Analyzable.objects.all().delete()

    @classproperty
    def model_class(cls) -> Type[Model]:
        return DomainDataModel

    def get_object(self):
        return self.model_class.objects.order_by("?").first().pk

    def test_get_superuser(self):
        plugin = self.get_object()
        self.assertIsNotNone(plugin)
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())


class IPDataModelViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/data_model/ip"

    @classproperty
    def model_class(cls) -> Type[Model]:
        return IPDataModel

    def get_object(self):
        return self.model_class.objects.order_by("?").first().pk

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        report = create_report(cls.user)
        report.data_model = cls.model_class.objects.create()
        report.save()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Analyzable.objects.all().delete()

    def test_get_superuser(self):
        plugin = self.get_object()
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())


class FileDataModelViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/data_model/file"

    @classproperty
    def model_class(cls) -> Type[Model]:
        return FileDataModel

    def get_object(self):
        return self.model_class.objects.order_by("?").first().pk

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        report = create_report(cls.user)
        report.data_model = cls.model_class.objects.create()
        report.save()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Analyzable.objects.all().delete()

    def test_get_superuser(self):
        plugin = self.get_object()
        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())
