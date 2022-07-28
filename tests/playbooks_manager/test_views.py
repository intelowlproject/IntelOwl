# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.playbooks_manager.serializers import PlaybookConfigSerializer

from .. import CustomAPITestCase


class PlaybookAppViewsTestCase(CustomAPITestCase):
    def test_get_playbook_config(self):
        response = self.client.get("/api/get_playbook_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), PlaybookConfigSerializer.read_and_verify_config()
        )
