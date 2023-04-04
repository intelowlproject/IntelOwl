# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from pydragonfly import Dragonfly, DragonflyException

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class DragonflyEmulation(FileAnalyzer):

    max_tries: int = 30
    poll_distance: int = 10
    operating_system: str
    profiles: list
    root: bool
    allow_actions: bool
    private: bool

    def config(self):
        super().config()
        # build analysis options
        self.analysis_options = {
            "profiles": self.profiles,
            "os": self.operating_system
            if self.operating_system in ["WINDOWS", "LINUX"]
            else None,
            "root": self.root,
            "allow_actions": self.allow_actions,
            "private": self.private,
        }
        # get secrets
        api_key: str = self._secrets["api_key_name"]
        api_url: str = self._secrets["url_key_name"]
        # init Dragonfly client instance
        self.df = Dragonfly(api_key=api_key)
        if api_url:
            self.df._server_url = api_url

    def run(self):
        try:
            # 1. upload sample for analysis
            logger.info(f"({repr(self)}) -> uploading file...")
            analysis_id = self.__upload()
            # 2. fetch and build full report
            logger.info(
                f"({repr(self)}, analysis_id: #{analysis_id}) -> poll & fetch result..."
            )
            return self.__poll_and_fetch_result(analysis_id)
        except DragonflyException as exc:
            raise AnalyzerRunException(str(exc))

    def __upload(self) -> int:
        """
        Submit sample for analysis and return analysis_id
        """
        response = self.df.Analysis.create(
            data=self.df.Analysis.CreateAnalysisRequestBody(
                **self.analysis_options,
            ),
            sample_name=self.filename,
            sample_buffer=self.read_file_bytes(),
        )
        return response.data["id"]

    def __poll_and_fetch_result(self, analysis_id: int) -> dict:
        """
        Retrieve analysis and corresponding report objects
        """
        result_obj = self.df.analysis_result(
            analysis_id=analysis_id,
            waiting_time=self.poll_distance,
            max_wait_cycle=self.max_tries,
        )

        return result_obj.asdict()

    @classmethod
    def _monkeypatch(cls):
        cls.max_tries = 0  # for test
        cls.poll_distance = 0  # for test
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.request",
                    side_effect=[
                        MockUpResponse(
                            {"id": 1, "malware_type": "PE"}, 201
                        ),  # __upload; sample ID
                        MockUpResponse({"id": 1}, 201),  # __upload; analysis ID
                        MockUpResponse(
                            {
                                "id": 1,
                                "created_at": "2022-01-17T12:07:55.446274Z",
                                "status": "ANALYZED",
                                "evaluation": "MALICIOUS",
                                "weight": 120,
                                "malware_families": ["Ransomware", "Trojan"],
                                "mitre_techniques": [
                                    {
                                        "tid": "tactic_tid",
                                        "name": "test_tactic",
                                        "techniques": [
                                            {
                                                "tid": "technique_tid",
                                                "name": "test_technique",
                                            }
                                        ],
                                    }
                                ],
                                "sample": {"id": 1, "filename": "test"},
                                "reports": [
                                    {
                                        "id": 1,
                                        "error": "Internal error",
                                        "profile": {"id": 1, "filename": "test.ql"},
                                    },
                                ],
                                "gui_url": "dragonfly.certego.net/analysis/1",
                                "api_url": "dragonfly.certego.net/api/analysis/1",
                            },
                            200,
                        ),  # __poll_and_fetch_result; Analysis.retrieve
                        MockUpResponse(
                            [{"id": 1, "rule": "testrule", "weight": 0, "matches": []}],
                            200,
                        ),  # __poll_and_fetch_result; Report.matched_rules
                    ],
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
