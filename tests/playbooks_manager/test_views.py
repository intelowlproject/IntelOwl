# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.playbooks_manager.models import PlaybookReport
from api_app.playbooks_manager.serializers import PlaybookConfigSerializer

from .. import CustomAPITestCase, PluginActionViewsetTestCase


class PlaybookAppViewsTestCase(CustomAPITestCase):
    def test_get_playbook_config(self):
        response = self.client.get("/api/get/get_playbook_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), PlaybookConfigSerializer.read_and_verify_config()
        )

class PlaybookActionViewSetTests(CustomAPITestCase, PluginActionViewsetTestCase):
    @property
    def plugin_type(self):
        return "playbook"

    @property
    def report_model(self):
        return PlaybookReport
