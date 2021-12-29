# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
import re

import requests
from requests.structures import CaseInsensitiveDict

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class DehashedSearch(ObservableAnalyzer):
    """
    Search a keyword on dehashed.com's search API.
    - API key is mandatory for dehased.com's API.
    """

    base_url: str = "https://api.dehashed.com/"

    def set_params(self, params):
        self.size = params.get("size", 1000)
        self.pages = params.get("pages", 1)

    def run(self):
        self.__auth = self._secrets["api_key_name"]
        if not self.__auth:
            raise AnalyzerConfigurationException(
                "No secret retrieved for `api_key_name`."
            )

        # try to identify search operator
        operator = self.__identify_search_operator()
        if operator:
            value = f"{operator}:{self.observable_name}"
        else:
            # if operator couldn't be identified, we can query without it
            value = self.observable_name

        # execute searches
        entries = self.__search(value)

        return {
            "query_value": value,
            "pages_queried": self.pages,
            "entries": entries,
        }

    def __identify_search_operator(self) -> str:
        operator = "name"
        if self.observable_classification == "ip":
            operator = "ip_address"
        elif self.observable_classification == "domain":
            operator = "domain"
        elif self.observable_classification == "url":
            operator = "domain"
        elif self.observable_classification == "generic":
            if re.match(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", self.observable_name):
                operator = "email"

        return operator

    def __search(self, value: str) -> list:
        # the API uses basic auth so we need to base64 encode the auth payload
        auth_b64 = base64.b64encode(self.__auth.encode()).decode()
        # construct headers
        headers = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "Authorization": f"Basic {auth_b64}",
                "User-Agent": "IntelOwl",
            }
        )
        url = f"{self.base_url}search?query={value}&size={self.size}"

        total_entries = []
        for page_no in range(1, self.pages + 1):
            try:
                logger.info(
                    f"{self.__repr__()} -> fetching search results for page #{page_no}"
                )
                resp = requests.get(f"{url}&page={page_no}", headers=headers)
                resp.raise_for_status()
            except requests.RequestException as e:
                raise AnalyzerRunException(e)
            else:
                entries_fetched = resp.json().get("entries", None)
                if not entries_fetched:
                    entries_fetched = []
                else:
                    total_entries.extend(entries_fetched)
                logger.info(f"{self.__repr__()} -> got {len(entries_fetched)} entries")

        return total_entries

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({"entries": [{"id": "test"}]}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
