# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.analyzers_manager.observable_analyzers.triage.triage_base import (
    TriageMixin,
)
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class TriageSearch(ObservableAnalyzer, TriageMixin):
    analysis_type: str

    def run(self):
        if self.analysis_type == "search":
            self.__triage_search()
        elif self.analysis_type == "submit":
            self.__triage_submit()
        else:
            raise AnalyzerConfigurationException(
                f"analysis type '{self.analysis_type}' not supported. Supported are: 'search', 'submit'."
            )

        return self.final_report

    def __triage_search(self):
        if self.observable_classification == Classification.HASH:
            query = self.observable_name
        else:
            query = f"{self.observable_classification}:{self.observable_name}"
        params = {"query": query}

        self.response = self.session.get(self.url + "search", params=params)

        self.final_report = self.response.json()

    def __triage_submit(self):
        data = {
            "kind": Classification.URL,
            Classification.URL: f"{self.observable_name}",
        }

        logger.info(f"triage {self.observable_name} sending URL for analysis")
        for _try in range(self.max_tries):
            logger.info(f"triage {self.observable_name} polling for result try #{_try + 1}")
            self.response = self.session.post(self.url + "samples", json=data)
            if self.response.status_code == 200:
                break
            time.sleep(self.poll_distance)

        if self.response:
            self.response.raise_for_status()
            self.manage_submission_response()
        else:
            raise AnalyzerRunException(f"response not available for {self.observable_name}")
