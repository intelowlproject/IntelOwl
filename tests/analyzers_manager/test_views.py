# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.models import Job


from .. import CustomAPITestCase, PluginActionViewsetTestCase


class AnalyzerAppViewsTestCase(CustomAPITestCase):
    def test_get_analyzer_config(self):
        response = self.client.get("/api/get_analyzer_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), AnalyzerConfigSerializer.read_and_verify_config()
        )


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @classmethod
    def setUpClass(cls):
        super(AnalyzerActionViewSetTests, cls).setUpClass()

    def setUp(self):
        super(AnalyzerActionViewSetTests, self).setUp()
        self.report = self.init_report()
        self.plugin_type = "analyzer"

    def init_report(self, status=None) -> AnalyzerReport:
        _job = Job.objects.create(status="running")
        _report, _ = AnalyzerReport.objects.get_or_create(
            **{
                "job_id": _job.id,
                "analyzer_name": "MISP",
                "status": AnalyzerReport.Statuses.PENDING.name
                if status is None
                else status,
                "task_id": "4b77bdd6-d05b-442b-92e8-d53de5d7c1a9",
            }
        )
        return _report
