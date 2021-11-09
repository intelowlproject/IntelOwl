# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import time

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class IntelX(ObservableAnalyzer):
    """
    Analyzer Name: `IntelX_Phonebook`\n
    Query URL: https://2.intelx.io/phonebook/search\n
    Requires API Key
    """

    base_url: str = "https://2.intelx.io/phonebook/search"

    def set_params(self, params):
        self._rows_limit = int(params.get("rows_limit", 100))
        self._timeout = int(params.get("timeout", 10))
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        session = requests.Session()
        session.headers.update({"x-key": self.__api_key, "User-Agent": "IntelOwl/v3.x"})
        params = {
            "term": self.observable_name,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": self._rows_limit,
            "timeout": self._timeout,
            "sort": 4,
            "media": 0,
            "terminate": [],
            "target": 0,
        }
        # POST the search term --> Fetch the 'id' --> GET the results using the 'id'
        r = session.post(self.base_url, json=params)
        r.raise_for_status()
        search_id = r.json().get("id", None)
        if not search_id:
            raise AnalyzerRunException(
                f"Failed to request search. Status code: {r.status_code}."
            )
        time.sleep(self._timeout + 5)  # wait a lil extra than timeout
        r = session.get(
            f"{self.base_url}/result?id={search_id}&limit={self._rows_limit}&offset=-1"
        )
        r.raise_for_status()
        selectors = r.json()["selectors"]
        parsed_selectors = self.__pb_search_results(selectors)
        return {"id": search_id, **parsed_selectors}

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
