import logging
import time
from copy import deepcopy

from pydragonfly import Dragonfly, DragonflyException, TParams

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class DragonflyEmulation(FileAnalyzer):
    def set_params(self, params):
        # max no. of tries when polling for result
        self.max_tries = 30
        # max 5 minutes waiting
        self.poll_distance = 10
        # build analysis options
        os = params.get("operating_system", None)
        self.analysis_options = {
            "profiles": params.get("profiles", []),
            "os": os if os in ["WINDOWS", "LINUX"] else None,
            "root": params.get("root", False),
            "allow_actions": params.get("allow_actions", False),
            "private": params.get("private", False),
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
            # 2. wait for analysis to finish
            logger.info(
                f"({repr(self)}) -> analysis_id: #{analysis_id} -> starting polling..."
            )
            self.__poll_status(analysis_id)
            # 3. fetch and build full report
            logger.info(
                f"({repr(self)}) -> analysis_id: #{analysis_id} -> fetching report..."
            )
            result = self.__fetch_and_build_result(analysis_id)
            return result
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

    def __poll_status(self, analysis_id: int) -> None:
        """
        Poll for analysis status until it finishes.
        """
        for chance in range(self.max_tries):
            time.sleep(self.poll_distance)
            logger.info(
                f"({self.__repr__()}) -> POLLING: try#{chance + 1}."
                f"...starting the query..."
            )
            response = self.df.Analysis.retrieve(
                object_id=analysis_id, params=TParams(fields=["id", "status"])
            )
            status = response.data.get("status", False)
            logger.info(
                f"({self.__repr__()}) -> POLLING: try#{chance + 1}."
                f"...status: '{status}'"
            )
            if status in ["FAILED", "ANALYZED", "REVOKED"]:
                break

    def __fetch_and_build_result(self, analysis_id: int) -> dict:
        """
        Retrieve analysis and corresponding report objects
        """
        # fetch analysis object
        response = self.df.Analysis.retrieve(
            object_id=analysis_id,
            params=TParams(
                fields=[
                    "id",
                    "created_at",
                    "evaluation",
                    "status",
                    "weight",
                    "malware_families",
                    "malware_behaviours",
                    "api_url",
                    "gui_url",
                    "sample",
                    "reports.id",
                    "reports.weight",
                    "reports.status",
                    "reports.evaluation",
                    "reports.error",
                    "reports.profile",
                ],
                expand=["reports", "reports.profile"],
            ),
        )
        analysis = deepcopy(response.data)

        # fetch matched_rules for corresponding report objects
        for idx in range(len(analysis["reports"])):
            report_id = analysis["reports"][idx]["id"]
            _resp = self.df.Report.matched_rules(
                object_id=report_id
            )  # fetch matched_rules
            analysis["reports"][idx]["matched_rules"] = [
                {field: rule[field] for field in ["id", "rule", "weight", "matches"]}
                for rule in _resp.data
            ]  # filter out the fields we need

        return analysis

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.request",
                    side_effect=[
                        MockResponse(
                            {"id": 1, "malware_type": "PE"}, 201
                        ),  # __upload; sample ID
                        MockResponse({"id": 1}, 201),  # __upload; analysis ID
                        MockResponse(
                            {"id": 1, "status": "ANALYZED"}, 200
                        ),  # __poll_status
                        MockResponse(
                            {"id": 1, "status": "ANALYZED", "reports": [{"id": 1}]}, 200
                        ),  # __fetch_and_build_result
                        MockResponse(
                            [{"id": 1, "rule": "testrule", "weight": 0, "matches": []}],
                            200,
                        ),  # __fetch_and_build_result
                    ],
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
