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

    def test_analyze_multiple_files(self):
        playbooks_to_run = ["FREE_TO_USE_ANALYZERS"]
        json = {
            "observables":[["ip","1.1.1.1"]],
            "observable_classification":"ip",
            "playbooks_requested":playbooks_to_run,
        }
        response = self.client.post("/api/playbook/analyze_multiple_files", data=json)
        response_json = response.json()
        playbooks_running = response_json.get("playbooks_running")

        print(response_json)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(playbooks_running, playbooks_to_run)
