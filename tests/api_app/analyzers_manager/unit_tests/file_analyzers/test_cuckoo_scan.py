from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.cuckoo_scan import CuckooAnalysis

from .base_test_class import BaseFileAnalyzerTest


class TestCuckooAnalysis(BaseFileAnalyzerTest):
    analyzer_class = CuckooAnalysis

    def get_mocked_response(self):
        # Mock Session and its methods
        mock_session = MagicMock()

        # Mock POST response (submit file)
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {"task_id": 123}
        mock_session.post.return_value = mock_post_response

        # Mock GET for polling -> "reported" status
        mock_poll_response = MagicMock()
        mock_poll_response.json.return_value = {"task": {"status": "reported"}}

        # Mock GET for final report
        mock_report_response = MagicMock()
        mock_report_response.json.return_value = {
            "signatures": [],
            "suricata": {"alerts": []},
            "network": {"http": [], "domains": [], "dns": []},
            "info": {"score": 5, "machine": {}, "id": "cuckoo123"},
            "target": {"file": {"type": "exe", "yara": []}},
        }

        # Order of GET calls: first poll, then report
        mock_session.get.side_effect = [mock_poll_response, mock_report_response]

        # Patch requests.Session to return our mocked session
        return patch(
            "api_app.analyzers_manager.file_analyzers.cuckoo_scan.requests.Session",
            return_value=mock_session,
        )

    def get_extra_config(self):
        # Create a hardcoded fake session for direct injection
        fake_session = MagicMock()
        fake_post = MagicMock()
        fake_post.status_code = 200
        fake_post.json.return_value = {"task_id": 123}
        fake_session.post.return_value = fake_post

        fake_poll = MagicMock()
        fake_poll.json.return_value = {"task": {"status": "reported"}}
        fake_report = MagicMock()
        fake_report.json.return_value = {
            "signatures": [],
            "suricata": {"alerts": []},
            "network": {"http": [], "domains": [], "dns": []},
            "info": {"score": 5, "machine": {}, "id": "cuckoo123"},
            "target": {"file": {"type": "exe", "yara": []}},
        }
        fake_session.get.side_effect = [fake_poll, fake_report]

        return {
            "_api_key_name": "dummy_key",
            "_url_key_name": "http://fake-cuckoo/",
            "max_post_tries": 1,
            "max_poll_tries": 1,
            "session": fake_session,  # 👈 directly attach session
        }
