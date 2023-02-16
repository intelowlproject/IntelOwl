# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from certego_saas.apps.user.models import User

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class AnalyzerAppViewsTestCase(CustomAPITestCase):
    def test_get_analyzer_config(self):
        response = self.client.get("/api/get_analyzer_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(),
            AnalyzerConfigSerializer.read_and_verify_config(user=self.superuser),
        )

    def test_analyzer_healthcheck_200(self):
        response = self.client.get("/api/analyzer/ClamAV/healthcheck")
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

    def test_analyzer_healthcheck_403(self):
        standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.client.force_authenticate(standard_user)

        response = self.client.post("/api/analyzer/ClamAV/update")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 403, msg=msg)
        standard_user.delete()

    def test_analyzer_update_200(self):
        response = self.client.post("/api/analyzer/Yara/update")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 200, msg=msg)

    def test_analyzer_update_400(self):
        response = self.client.post("/api/analyzer/Xlm_Macro_Deobfuscator/update")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "No update implemented"}, msg=msg
        )

        response = self.client.post("/api/analyzer/Analyzer404/update")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 400, msg=msg)
        self.assertDictEqual(
            content["errors"], {"detail": "Analyzer doesn't exist"}, msg=msg
        )

    def test_analyzer_update_403(self):
        standard_user = User.objects.create_user(
            username="standard_user",
            email="standard_user@intelowl.com",
            password="test",
        )
        self.client.force_authenticate(standard_user)

        response = self.client.post("/api/analyzer/Yara/update")
        content = response.json()
        msg = (response, content)

        self.assertEqual(response.status_code, 403, msg=msg)
        standard_user.delete()


class AnalyzerActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @property
    def plugin_type(self):
        return "analyzer"

    @property
    def report_model(self):
        return AnalyzerReport
