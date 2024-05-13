# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from typing import Type
from unittest.mock import patch

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from tests import CustomViewSetTestCase, PluginActionViewsetTestCase
from tests.api_app.test_views import AbstractConfigViewSetTestCaseMixin


class AnalyzerConfigViewSetTestCase(
    AbstractConfigViewSetTestCaseMixin, CustomViewSetTestCase
):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    URL = "/api/analyzer"

    @classmethod
    @property
    def model_class(cls) -> Type[AnalyzerConfig]:
        return AnalyzerConfig

    def test_pull(self):
        from api_app.analyzers_manager.file_analyzers.yara_scan import YaraScan

        analyzer = "Yara"
        response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(self.superuser)

        with patch.object(YaraScan, "update", return_value=True):
            response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 200, response.json())
        result = response.json()
        self.assertIn("status", result)
        self.assertTrue(result["status"])

        analyzer = "Doc_Info"
        response = self.client.post(f"{self.URL}/{analyzer}/pull")
        self.assertEqual(response.status_code, 400)
        result = response.json()
        print(result)
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(
            result["errors"]["detail"], "This Plugin has no Update implemented"
        )

    def test_health_check(self):
        analyzer = "ClamAV"
        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 200)

        self.client.force_authenticate(self.superuser)

        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn("status", result)

        analyzer = "Xlm_Macro_Deobfuscator"
        response = self.client.get(f"{self.URL}/{analyzer}/health_check")
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertIn("errors", result)
        self.assertIn("detail", result["errors"])
        self.assertEqual(result["errors"]["detail"], "No healthcheck implemented")


class AnalyzerActionViewSetTests(CustomViewSetTestCase, PluginActionViewsetTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @property
    def plugin_type(self):
        return "analyzer"

    def init_report(self, status: str, user) -> AnalyzerReport:
        config = AnalyzerConfig.objects.get(name="HaveIBeenPwned")
        _job = Job.objects.create(
            user=user,
            status=Job.Status.RUNNING,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
        )
        _job.analyzers_to_execute.set([config])
        _report, _ = AnalyzerReport.objects.get_or_create(
            **{
                "job_id": _job.id,
                "status": status,
                "config": config,
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
                "parameters": {},
            }
        )
        return _report
