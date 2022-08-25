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

    def test_analyze_multiple_observables(self):
        playbooks_to_run = ["FREE_TO_USE_ANALYZERS"]
        data = {
            "observables": [["ip", "1.1.1.1"]],
            "playbooks_requested": playbooks_to_run,
        }
        response = self.client.post(
            "/api/playbook/analyze_multiple_observables", data, format="json"
        )
        response_json = response.json()
        playbooks_running = response_json.get("playbooks_running")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(playbooks_running, playbooks_to_run)

    # There is still space for file playbooks left here.
    # I will be implementing them after we have a standard
    # file analyzer to ourselves.
