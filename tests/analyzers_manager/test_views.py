# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

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
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_analyzer_healthcheck_400(self):
        # non docker based analyzer
        response = self.client.get("/api/analyzer/MISP/healthcheck")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "No healthcheck implemented"}, msg=msg
        )

        # non-existing analyzer
        response = self.client.get("/api/analyzer/Analyzer404/healthcheck")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "Analyzer doesn't exist"}, msg=msg
        )


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @property
    def plugin_type(self):
        return "analyzer"

    @property
    def report_model(self):
        return AnalyzerReport
