import re
from logging import getLogger
from typing import Dict
from urllib.parse import urlparse

import dateparser
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = getLogger(__name__)

_supported_fuzzy_params = [
    "swap",
    "omit",
    "repeat",
    "add",
    "typo",
    "bitflip",
    "hyphen",
    "fatfinger",
    "subdomain",
    "vowels",
    "homoglyph",
    "all",
]

_supported_sort_types = [
    "first_seen",
    "last_seen",
]

_supported_format_types = [
    "json",
    "dig",
]

_min_limit_value = 0
_max_limit_value = 50000

_min_offset_value = 0


class DNS0Names(classes.ObservableAnalyzer):
    base_url: str = "https://api.dns0.eu/names"

    _api_key: str
    query: str
    root: bool
    fuzzy: list[str]
    from_date: str
    to_date: str
    not_before: str
    sort: str
    format: str
    limit: int
    offset: int

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self._validate_params()

    def run(self):
        params = self._create_params()
        headers = self._create_headers()

        response = requests.get(self.base_url, params=params, headers=headers)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise AnalyzerRunException(e)

        return response.json()

    def _create_headers(self):
        headers = {
            "Accept": "application/json",
        }
        if hasattr(self, "_api_key") and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _validate_params(self):
        if hasattr(self, "fuzzy") and any(
            fuzzy_params not in _supported_fuzzy_params for fuzzy_params in self.fuzzy
        ):
            raise AnalyzerConfigurationException(
                "Fuzzy type not supported! "
                "The list of supported fuzzy is at: "
                "https://docs.dns0.eu/dns-api/names#fuzziness"
            )

        if hasattr(self, "sort") and self.sort not in _supported_sort_types:
            raise AnalyzerConfigurationException(
                f"Sort type {self.sort} not supported! "
                f"Available sort types are: {_supported_sort_types}"
            )

        if hasattr(self, "format") and self.format not in _supported_format_types:
            raise AnalyzerConfigurationException(
                f"Format type {self.format} not supported! "
                f"Available format types are: {_supported_format_types}"
            )

        if (
            hasattr(self, "limit")
            and not _min_limit_value < self.limit <= _max_limit_value
        ):
            raise AnalyzerConfigurationException(
                f"{self.limit} is out of bound! "
                f"Max value is {_max_limit_value}, min value is {_min_limit_value}"
            )

        if hasattr(self, "offset") and self.offset < _min_offset_value:
            raise AnalyzerConfigurationException(
                f"{self.offset} can't be below {_min_offset_value}"
            )

    @staticmethod
    def convert_date_type(date_string):
        if not date_string:
            return False

        date_parsed = (
            DNS0Names.convert_unix_timestamp(date_string)
            or DNS0Names.convert_relative_date(date_string)
            or DNS0Names.convert_date(date_string)
        )
        if not date_parsed:
            raise AnalyzerRunException("Error in date format!")
        return date_parsed

    @staticmethod
    def convert_relative_date(date):
        # accepts string matching the format:
        # - at the beginning
        # a number
        # a character indicating Year, Month or Day
        pattern = re.compile(r"-\d+[YMD]")
        if match := pattern.match(date):
            return match.group()
        return False

    @staticmethod
    def convert_date(date):
        pattern = re.compile(r"^(\d{4}-\d{2}-\d{2})$")
        if match := pattern.match(date):
            return dateparser.parse(match.group())
        return False

    @staticmethod
    def convert_unix_timestamp(timestamp):
        try:
            return str(int(timestamp))
        except Exception:
            return False

    def _create_params(self):
        target_observable = self.observable_name
        if self.observable_classification == self.ObservableTypes.URL:
            target_observable = urlparse(self.observable_name).hostname
        params = {"q": target_observable}

        # convert root parameter into 1 or 0
        if hasattr(self, "root") and self.root:
            params["root"] = int(self.root)

        # pass list of fuzzy parameter
        if hasattr(self, "fuzzy") and self.fuzzy:
            params["fuzzy"] = self.fuzzy

        # convert dates to correct format
        if hasattr(self, "from_date") and self.from_date:
            if result := self.convert_date_type(self.from_date):
                params["from"] = result

        if hasattr(self, "to_date") and self.to_date:
            if result := self.convert_date_type(self.to_date):
                params["to"] = result

        if hasattr(self, "not_before") and self.not_before:
            if result := self.convert_date_type(self.not_before):
                params["not_before"] = result

        if hasattr(self, "sort") and self.sort:
            params["sort"] = self.sort

        if hasattr(self, "format") and self.format:
            params["format"] = self.format

        if hasattr(self, "limit") and self.limit:
            params["limit"] = self.limit

        if hasattr(self, "offset") and self.offset:
            params["offset"] = self.offset

        return params

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
