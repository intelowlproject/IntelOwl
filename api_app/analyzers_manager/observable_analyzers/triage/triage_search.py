# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.observable_analyzers.triage.triage_base import (
    TriageMixin,
)
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class TriageSearch(ObservableAnalyzer, TriageMixin):
    def run(self):
        if self.analysis_type == "search":
            self.__triage_search()
        elif self.analysis_type == "submit":
            self.__triage_submit()
        else:
            raise AnalyzerConfigurationException(
                f"analysis type '{self.analysis_type}' not supported."
                "Supported are: 'search', 'submit'."
            )

        return self.final_report

    def __triage_search(self):
        if self.observable_classification == self.ObservableTypes.HASH:
            query = self.observable_name
        else:
            query = f"{self.observable_classification}:{self.observable_name}"
        params = {"query": query}

        response = self.session.get(self.base_url + "search", params=params)

        self.final_report = response

    def __triage_submit(self):
        data = {"kind": "url", "url": f"{self.observable_name}"}

        logger.info(f"triage {self.observable_name} sending URL for analysis")
        response = None
        for _try in range(self.max_tries):
            logger.info(
                f"triage {self.observable_name} polling for result try #{_try + 1}"
            )
            response = self.session.post(self.base_url + "samples", json=data)
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        if response:
            self.manage_submission_response(response)
        else:
            raise AnalyzerRunException(
                f"response not available for {self.observable_name}"
            )

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse(
                        {"tasks": {"task_1": {}, "task_2": {}}, "data": []}, 200
                    ),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockResponse(
                        {"id": "sample_id", "status": "pending"}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
