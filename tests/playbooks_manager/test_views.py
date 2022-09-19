# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import os

from api_app.playbooks_manager.serializers import PlaybookConfigSerializer

from .. import CustomAPITestCase


class PlaybookAppViewsTestCase(CustomAPITestCase):
    playbooks_to_run = ["FREE_TO_USE_ANALYZERS"]

    def test_get_playbook_config(self):
        response = self.client.get("/api/get_playbook_configs")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.json(), {})
        self.assertDictEqual(
            response.json(), PlaybookConfigSerializer.read_and_verify_config()
        )

    def test_analyze_multiple_all_observables(self):
        ip_observable_name = os.environ.get("TEST_IP", "1.1.1.1")
        url_observable_name = os.environ.get("TEST_URL", "https://google.com")
        domain_observable_name = os.environ.get("TEST_DOMAIN", "google.com")
        hash_observable_name = os.environ.get(
            "TEST_HASH", hashlib.md5(domain_observable_name)
        )
        generic_observable_name = "project@honeynet.org"

        data = {
            "observables": [
                ["ip", ip_observable_name],
                ["url", url_observable_name],
                ["domain", domain_observable_name],
                ["hash", hash_observable_name],
                ["generic", generic_observable_name],
            ],
            "playbooks_requested": self.playbooks_to_run,
        }
        response = self.client.post(
            "/api/playbook/analyze_multiple_observables", data, format="json"
        )
        results = response.json().get("results")
        for result in results:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(self.playbooks_to_run, result.get("playbooks_running"))
