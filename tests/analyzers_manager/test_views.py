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


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @classmethod
    def setUpClass(cls):
        super(AnalyzerActionViewSetTests, cls).setUpClass()

    def setUp(self):
        super(AnalyzerActionViewSetTests, self).setUp()
        self.report = self.init_report()
        self.plugin_type = "analyzer"

    def get_report_class(self):
        return AnalyzerReport
