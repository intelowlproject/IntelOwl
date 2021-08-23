# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.analyzers_manager.models import AnalyzerReport


from .. import CustomAPITestCase, PluginActionViewsetTestCase


class AnalyzerAppViewsTestCase(CustomAPITestCase):
    def test_get_analyzer_config(self):
        response = self.client.get("/api/get_analyzer_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), AnalyzerConfigSerializer.read_and_verify_config()
        )

    def test_analyzer_healthcheck_200(self):
        response = self.client.get("/api/analyzer/Rendertron/healthcheck")
        self.assertEqual(response.status_code, 200)

    def test_analyzer_healthcheck_400(self):
        # non docker analyzer
        response = self.client.get("/api/analyzer/MISP/healthcheck")
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.json(), {"detail": "No healthcheck implemented"})
        # non existing analyzer
        response = self.client.get("/api/analyzer/Analyzer404/healthcheck")
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(response.json(), {"detail": "Analyzer doesn't exist"})


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @classmethod
    def setUpClass(cls):
        super(AnalyzerActionViewSetTests, cls).setUpClass()

    def setUp(self):
        super(AnalyzerActionViewSetTests, self).setUp()
        self.report = self.init_report()
        self.plugin_type = "analyzer"

    @property
    def report_model(self):
        return AnalyzerReport
