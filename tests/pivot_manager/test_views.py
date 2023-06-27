from typing import Type

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job
from api_app.pivots_manager.models import Pivot, PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from tests import CustomViewSetTestCase
from tests.core.test_views import (
    AbstractConfigViewSetTestCaseMixin,
    ViewSetTestCaseMixin,
)


class PivotViewSetTestCase(ViewSetTestCaseMixin, CustomViewSetTestCase):
    URL = "/api/pivot"

    @classmethod
    @property
    def model_class(cls) -> Type[Pivot]:
        return Pivot

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

    def test_create(self):
        data = {
            "starting_job": self.j1.pk,
            "ending_job": self.j2.pk,
            "pivot_config": self.pc.pk,
        }
        response = self.client.post(self.URL, data=data)
        content = response.json()
        self.assertEqual(response.status_code, 400, content)
        self.assertIn("errors", content)
        self.assertIn("non_field_errors", content["errors"])
        self.assertCountEqual(
            [
                "The fields starting_job, pivot_config,"
                " ending_job must make a unique set."
            ],
            content["errors"]["non_field_errors"],
        )
        data = {
            "starting_job": self.j2.pk,
            "ending_job": self.j1.pk,
            "pivot_config": self.pc.pk,
        }
        response = self.client.post(self.URL, data=data)
        content = response.json()
        self.assertEqual(response.status_code, 400, content)
        self.assertIn("errors", content)
        self.assertIn("non_field_errors", content["errors"])
        self.assertCountEqual(
            ["You do not have permission to pivot these two jobs"],
            content["errors"]["non_field_errors"],
        )

        self.client.force_authenticate(self.superuser)
        response = self.client.post(self.URL, data=data)
        content = response.json()
        self.assertEqual(response.status_code, 201, content)

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
            field="test.0",
            analyzer_config=AnalyzerConfig.objects.first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.pivot = Pivot.objects.create(
            starting_job=self.j1, ending_job=self.j2, pivot_config=self.pc
        )

    def tearDown(self) -> None:
        super().tearDown()
        self.j1.delete()
        self.j2.delete()
        self.pc.delete()
        Pivot.objects.all().delete()


class PivotConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    URL = "/api/pivotconfig"

    def setUp(self):
        super().setUp()
        self.pc = PivotConfig(
            field="test.0",
            analyzer_config=AnalyzerConfig.objects.first(),
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

    def test_create(self):

        data = {
            "playbook_to_execute": self.pc.playbook_to_execute_id,
            "field": self.pc.field,
            "analyzer_config": self.pc.analyzer_config_id,
        }

        response = self.client.post(self.URL, data=data)
        content = response.json()
        self.assertEqual(400, response.status_code, content)
        self.assertIn("errors", content)
        self.assertIn("non_field_errors", content["errors"])
        self.assertCountEqual(
            [
                "The fields analyzer_config, field,"
                " playbook_to_execute must make a unique set."
            ],
            content["errors"]["non_field_errors"],
        )

        data = {
            "playbook_to_execute": self.pc.playbook_to_execute_id,
            "field": self.pc.field,
            "connector_config": ConnectorConfig.objects.first().pk,
        }
        response = self.client.post(self.URL, data=data)
        content = response.json()
        self.assertEqual(201, response.status_code, content)
        PivotConfig.objects.get(pk=content["id"]).delete()
