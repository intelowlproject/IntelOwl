# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
import re

import requests
from requests.structures import CaseInsensitiveDict

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class DehashedSearch(ObservableAnalyzer):
    """
    Search a keyword on dehashed.com's search API.
    - API key is mandatory for dehased.com's API.
    """

    url: str = "https://api.dehashed.com/"
    size: int
    pages: int
    operator: str
    _api_key_name: str

    def run(self):
        # try to identify search operator
        self.__identify_search_operator()
        if self.operator in ["name", "address"] and " " in self.observable_name:
            # this is to allow to do "match_phrase" queries
            # ex: "John Smith" would match the entire phrase
            # ex: John Smith would match also John alone
            # same for the addresses
            cleaned_observable_name = f'"{self.observable_name}"'
        else:
            cleaned_observable_name = self.observable_name
        value = f"{self.operator}:{cleaned_observable_name}"

        # execute searches
        entries = self.__search(value)

        logger.info(
            f"result for observable {self.observable_name} is: query:"
            f" {value}, pages {self.pages}, operator: {self.operator}"
        )

        return {
            "query_value": value,
            "pages_queried": self.pages,
            "operator": self.operator,
            "entries": entries,
        }

    def __identify_search_operator(self):
        if self.observable_classification == Classification.IP:
            self.operator = "ip_address"
        elif self.observable_classification in [
            Classification.DOMAIN,
            Classification.URL,
        ]:
            self.operator = "domain"
        elif self.observable_classification == Classification.GENERIC:
            if re.match(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", self.observable_name):
                self.operator = "email"
            # order matters! it's important "address" is placed before "phone"
            elif " " in self.observable_name and re.match(r"\d.*[a-zA-Z]|[a-zA-Z].*\d", self.observable_name):
                self.operator = "address"
            elif re.match(r"\+?\d+", self.observable_name):
                self.operator = "phone"
            elif " " in self.observable_name:
                self.operator = "name"

    def __search(self, value: str) -> list:
        # the API uses basic auth so we need to base64 encode the auth payload
        auth_b64 = base64.b64encode(self._api_key_name.encode()).decode()
        # construct headers
        headers = CaseInsensitiveDict(
            {
                "Accept": "application/json",
                "Authorization": f"Basic {auth_b64}",
                "User-Agent": "IntelOwl",
            }
        )
        url = f"{self.url}search?query={value}&size={self.size}"

        total_entries = []
        for page_no in range(1, self.pages + 1):
            logger.info(f"{self.__repr__()} -> fetching search results for page #{page_no}")
            resp = requests.get(f"{url}&page={page_no}", headers=headers)
            resp.raise_for_status()
            entries_fetched = resp.json().get("entries", None)
            if not entries_fetched:
                entries_fetched = []
            else:
                total_entries.extend(entries_fetched)
            logger.info(f"{self.__repr__()} -> got {len(entries_fetched)} entries")

        return total_entries
