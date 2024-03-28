from typing import Type

from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig, PivotMap
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomViewSetTestCase, ViewSetTestCaseMixin
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class PivotMapViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/pivot_map"

    @classmethod
    @property
    def model_class(cls) -> Type[PivotMap]:
        return PivotMap

    def get_object(self):
        return self.model_class.objects.order_by("?").first().pk

    def test_get(self):
        plugin = self.model_class.objects.order_by("?").first().pk
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 403, response.json())

        self.client.force_authenticate(None)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 401, response.json())

        self.client.force_authenticate(self.superuser)
        response = self.client.get(f"{self.URL}/{plugin}")
        self.assertEqual(response.status_code, 200, response.json())

    def setUp(self):
        super().setUp()
        self.j1 = Job.objects.create(
            user=self.superuser,
            observable_name="test.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.j2 = Job.objects.create(
            user=self.superuser,
            observable_name="test2.com",
            observable_classification="domain",
            status="reported_without_fails",
        )
        self.pc = PivotConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.pivot = PivotMap.objects.create(
            starting_job=self.j1, ending_job=self.j2, pivot_config=self.pc
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.j1.delete()
        self.j2.delete()
        self.pc.delete()
        PivotMap.objects.all().delete()


class PivotConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    URL = "/api/pivot"

    def setUp(self):
        super().setUp()
        self.pc = PivotConfig(
            name="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.pc.save()

    def tearDown(self) -> None:
        super().tearDown()
        self.pc.delete()

    @classmethod
    @property
    def model_class(cls) -> Type[PivotConfig]:
        return PivotConfig
