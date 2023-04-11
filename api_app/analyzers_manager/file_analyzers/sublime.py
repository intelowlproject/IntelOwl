from logging import getLogger
from typing import Dict
from unittest.mock import patch

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections

logger = getLogger(__name__)


class Sublime(FileAnalyzer):
    _api_key: str
    _message_source_id: str
    _url: str

    headers = {"accept": "application/json", "content-type": "application/json"}
    live_flow_endpoint = "/v1/live-flow/raw-messages/analyze"
    retrieve_message_endpoint = "/v0/messages"
    api_port = 8000
    gui_port = 3000

    def run(self) -> Dict:
        self.headers["Authorization"] = f"Bearer {self._api_key}"
        session = requests.Session()
        session.headers = self.headers
        result = session.post(
            f"{self._url}:{self.api_port}{self.live_flow_endpoint}",
            json={
                "create_mailbox": True,
                "raw_message": self._job.b64,
                "message_source_id": self._message_source_id,
                "mailbox_email_address": self._job.user.email,
                "labels": [self._job.user.username],
                "run_active_detection_rules": True,
                "run_all_detection_rules": False,
            },
        )
        try:
            result.raise_for_status()
        except requests.exceptions.RequestException:
            raise AnalyzerRunException(result.content)
        else:
            result_analysis = result.json()
            result_message = session.get(
                f"{self._url}:{self.api_port}{self.retrieve_message_endpoint}/"
                f"{result_analysis['message_id']}"
            )
            try:
                result_message.raise_for_status()
            except requests.exceptions.RequestException:
                self.report.errors.append(result_message.content)
                raise AnalyzerRunException(result_message.content)
            else:
                canonical_id = result_message.json()["canonical_id"]
                return {
                    "flagged_rules": [
                        {
                            key: rule[key]
                            for key in [
                                "name",
                                "description",
                                "severity",
                                "maturity",
                                "label",
                                "tags",
                                "false_positives",
                                "references",
                                "updated_at",
                                "authors",
                            ]
                        }
                        for rule in result_analysis["flagged_rules"]
                    ],
                    "gui_url": f"{self._url}:{self.gui_port}/messages/{canonical_id}",
                }

    @classmethod
    def _monkeypatch(cls):

        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockUpResponse({"canonical_id": "test"}, 200),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockUpResponse(
                        {
                            "message_id": "test",
                            "raw_message_id": "test",
                            "flagged_rules": [
                                {
                                    "id": "25ae5f27-dee3-4e72-b8b9-3b51d366d695",
                                    "internal_type": None,
                                    "org_id": "b92d89c9-0e04-41ff-9d7b-18a9249bb2ae",
                                    "type": "detection",
                                    "active": True,
                                    "source_md5": "b1b973ccc12158aad82a0c7cb78a4975",
                                    "exclusion_mql": None,
                                    "name": "Attachment: Malicious OneNote Commands",
                                    "authors": [
                                        {
                                            "name": "Kyle Parrish",
                                            "twitter": "Kyle_Parrish_",
                                        }
                                    ],
                                    "description": "Scans for OneNote attachments",
                                    "references": [],
                                    "tags": ["Suspicious attachment", "Malware"],
                                    "false_positives": None,
                                    "maturity": None,
                                    "severity": "high",
                                    "label": None,
                                    "created_by_api_request_id": None,
                                    "created_by_org_id": None,
                                    "created_by_org_name": None,
                                    "created_by_user_id": None,
                                    "created_by_user_name": None,
                                    "created_at": "2023-03-29 13:25:24.81853+00",
                                    "updated_at": "2023-03-29 13:25:24.81853+00",
                                    "active_updated_at": "2023-03-29T13:27:38.536457Z",
                                    "actions": None,
                                    "immutable": True,
                                    "feed_id": "Test",
                                    "feed_external_rule_id": "test",
                                }
                            ],
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
