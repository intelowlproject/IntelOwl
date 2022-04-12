# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import time

import requests
from django.utils.functional import cached_property

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class IntelX(ObservableAnalyzer):
    """
    Analyzer Name: `IntelX`\n
    Refer to: https://github.com/IntelligenceX/SDK
    Requires API Key
    """

    base_url: str = "https://2.intelx.io"

    def set_params(self, params):
        self._query_type = params.get("query_type", "phonebook")
        if self._query_type not in ["phonebook", "intelligent"]:
            raise AnalyzerConfigurationException(f"{self._query_type} not supported")
        self.url = self.base_url + f"/{self._query_type}/search"
        self._rows_limit = int(params.get("rows_limit", 1000))
        self._max_tries = int(params.get("max_tries", 10))
        self._poll_distance = int(params.get("poll_distance", 3))
        self._timeout = int(params.get("timeout", 10))
        self._datefrom = params.get("datefrom", "")
        self._dateto = params.get("dateto", "")
        self.__api_key = self._secrets["api_key_name"]

    @cached_property
    def _session(self):
        session = requests.Session()
        session.headers.update({"x-key": self.__api_key, "User-Agent": "IntelOwl"})
        return session

    def _poll_for_results(self, search_id):
        json_data = {}
        for chance in range(self._max_tries):
            time.sleep(self._poll_distance)
            logger.info(
                f"Result Polling. Try #{chance + 1}. Starting the query..."
                f"<-- {self.__repr__()}"
            )
            try:
                r = self._session.get(
                    f"{self.url}/result?id={search_id}"
                    f"&limit={self._rows_limit}&offset=-1"
                )
                r.raise_for_status()
            except requests.RequestException as e:
                logger.warning(f"request failed: {e}")
            else:
                if r.status_code == 200:
                    json_data = r.json()
                    break

        if not json_data:
            raise AnalyzerRunException(
                "reached max tries for IntelX analysis,"
                f" observable {self.observable_name}"
            )

        if self._query_type == "phonebook":
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
            "maxresults": self._rows_limit,
            "timeout": self._timeout,
            "sort": 4,  # newest items first
            "media": 0,
            "terminate": [],
        }
        if self._query_type == "phonebook":
            params["target"] = 0
        elif self._query_type == "intelligent":
            params["datefrom"] = self._datefrom
            params["dateto"] = self._dateto
        # POST the search term --> Fetch the 'id' --> GET the results using the 'id'
        logger.info(
            f"starting {self._query_type} request for observable {self.observable_name}"
        )
        r = self._session.post(self.url, json=params)
        r.raise_for_status()
        search_id = r.json().get("id", None)
        if not search_id:
            raise AnalyzerRunException(
                f"Failed to request search. Status code: {r.status_code}."
            )
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.post",
                    return_value=MockResponse({"id": 1}, 200),
                ),
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"selectors": []}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
