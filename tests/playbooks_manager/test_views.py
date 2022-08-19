# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.playbooks_manager.serializers import PlaybookConfigSerializer

from .. import CustomAPITestCase


# curl 'http://192.46.215.97/api/playbook/analyze_multiple_observables' \
#   -H 'Accept: application/json, text/plain, */*' \
#   -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \
#   -H 'Authorization: Token 2db86cb6e0ee0a78982e5fe00bacf487' \
#   -H 'Connection: keep-alive' \
#   -H 'Content-Type: application/json' \
#   -H 'Origin: http://192.46.215.97' \
#   -H 'Referer: http://192.46.215.97/scan' \
#   -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36' \
#   --data-raw '{"observables":[["ip","1.1.1.1"]],"observable_classification":"ip","playbooks_requested":["FREE_TO_USE_ANALYZERS"]}' \
#   --compressed \
#   --insecure

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
