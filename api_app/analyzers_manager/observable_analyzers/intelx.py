# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time
from typing import Dict

import requests
from django.utils.functional import cached_property

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)

logger = logging.getLogger(__name__)


class IntelX(ObservableAnalyzer):
    """
    Analyzer Name: `IntelX`\n
    Refer to: https://github.com/IntelligenceX/SDK
    Requires API Key
    """

    url: str = "https://2.intelx.io"

    _api_key_name: str

    query_type: str
    rows_limit: int
    max_tries: int
    poll_distance: int
    timeout: int
    datefrom: str
    dateto: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.query_type not in ["phonebook", "intelligent"]:
            raise AnalyzerConfigurationException(f"{self.query_type} not supported")
        self.search_url = self.url + f"/{self.query_type}/search"

    @cached_property
    def _session(self):
        session = requests.Session()
        session.headers.update({"x-key": self._api_key_name, "User-Agent": "IntelOwl"})
        return session

    def _poll_for_results(self, search_id):
        json_data = {}
        for chance in range(self.max_tries):
            logger.info(f"Result Polling. Try #{chance + 1}. Starting the query...<-- {self.__repr__()}")
            try:
                r = self._session.get(
                    f"{self.search_url}/result?id={search_id}&limit={self.rows_limit}&offset=-1"
                )
                r.raise_for_status()
            except requests.RequestException as e:
                logger.warning(f"request failed: {e}")
            else:
                if r.status_code == 200:
                    json_data = r.json()
                    break
            time.sleep(self.poll_distance)

        if not json_data:
            raise AnalyzerRunException(
                f"reached max tries for IntelX analysis, observable {self.observable_name}"
            )

        if self.query_type == "phonebook":
            selectors = json_data["selectors"]
            parsed_selectors = self.__pb_search_results(selectors)
            result = {"id": search_id, **parsed_selectors}
        else:
            result = json_data
        return result

    def run(self):
        params = {
            "term": self.observable_name,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": self.rows_limit,
            "timeout": self.timeout,
            "sort": 4,  # newest items first
            "media": 0,
            "terminate": [],
        }
        if self.query_type == "phonebook":
            params["target"] = 0
        elif self.query_type == "intelligent":
            params["datefrom"] = self.datefrom
            params["dateto"] = self.dateto
        # POST the search term --> Fetch the 'id' --> GET the results using the 'id'
        logger.info(f"starting {self.query_type} request for observable {self.observable_name}")
        r = self._session.post(self.search_url, json=params)
        r.raise_for_status()
        search_id = r.json().get("id", None)
        if not search_id:
            raise AnalyzerRunException(f"Failed to request search. Status code: {r.status_code}.")
        result = self._poll_for_results(search_id)

        return result

    @staticmethod
    def __pb_search_results(selectors):
        """
        https://github.com/zeropwn/intelx.py/blob/master/cli/intelx.py#L89
        """
        result = {}
        for block in selectors:
            selectortypeh = block["selectortypeh"]
            if selectortypeh not in result:
                result[selectortypeh] = []
            result[selectortypeh].append(block["selectorvalue"])

        return result
