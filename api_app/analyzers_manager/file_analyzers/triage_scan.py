# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.observable_analyzers.triage.triage_base import (
    TriageMixin,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class TriageScanFile(FileAnalyzer, TriageMixin):
    def run(self):
        name_to_send = self.filename if self.filename else self.md5
        binary = self.read_file_bytes()
        files = {
            "file": (name_to_send, binary),
            "_json": (None, b'{"kind": "file", "interactive": false}'),
        }

        logger.info(f"triage md5 {self.md5} sending sample for analysis")
        for _try in range(self.max_tries):
            logger.info(f"triage md5 {self.md5} polling for result try #{_try + 1}")
            self.response = self.session.post(self.url + "samples", files=files)
            if self.response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        if self.response:
            self.manage_submission_response()
        else:
            raise AnalyzerRunException(f"response not available for {self.md5}")

        return self.final_report

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockUpResponse(
                        {"tasks": {"task_1": {}, "task_2": {}}}, 200
                    ),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockUpResponse(
                        {"id": "sample_id", "status": "pending"}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
