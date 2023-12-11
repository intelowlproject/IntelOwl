from logging import getLogger
from typing import Dict
from urllib.parse import urlparse

import requests
from dateutil import parser as dateutil_parser

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


class DNS0(classes.ObservableAnalyzer):
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

        if not hasattr(self, "_api_key") or self._api_key:
            raise AnalyzerRunException("No API key specified")

        self._validate_params()

    def run(self):
        params = self._create_params()
        headers = {
            "Authorization": f"Bearer {self._api_key}",
        }

        response = requests.get(self.base_url, params=params, headers=headers)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise AnalyzerRunException(e)

        return response.json()

    def _validate_params(self):
        if not hasattr(self, "fuzzy") or any(
            fuzzy_params not in _supported_fuzzy_params for fuzzy_params in self.fuzzy
        ):
            raise AnalyzerConfigurationException(
                "Fuzzy type not supported! "
                "The list of supported fuzzy is at: "
                "https://docs.dns0.eu/dns-api/names#fuzziness"
            )

        if not hasattr(self, "sort") or self.sort not in _supported_sort_types:
            raise AnalyzerConfigurationException(
                f"Sort type {self.sort} not supported! "
                f"Available sort types are: {_supported_sort_types}"
            )

        if not hasattr(self, "format") or self.format not in _supported_format_types:
            raise AnalyzerConfigurationException(
                f"Format type {self.format} not supported! "
                f"Available format types are: {_supported_format_types}"
            )

        if (
            not hasattr(self, "limit")
            or not _min_limit_value < self.limit <= _max_limit_value
        ):
            raise AnalyzerConfigurationException(
                f"{self.limit} is out of bound! "
                f"Max value is {_max_limit_value}, min value is {_min_limit_value}"
            )

        if not hasattr(self, "offset") or self.offset < _min_offset_value:
            raise AnalyzerConfigurationException(
                f"{self.offset} can't be below {_min_offset_value}"
            )

    @staticmethod
    def convert_date_type(date_string):
        # TODO: add support for UNIX timestamp and relative dates
        if not date_string:
            return False

        try:
            return dateutil_parser.parse(date_string).strftime("%Y-%m-%d")
        except ValueError:
            error_message = f"{date_string} cannot be converted to a valid datetime"
        except TypeError:
            error_message = (
                f"{type(date_string)} is not a string and cannot be "
                f"converted to a datetime "
            )
        except Exception:
            error_message = (
                f"{date_string} with type: {type(date_string)},"
                f"something wrong happened during conversion to datetime"
            )

        raise AnalyzerRunException(error_message)

    def _create_params(self):
        target_observable = self.observable_name
        if self.observable_classification == self.ObservableTypes.IP:
            raise AnalyzerRunException("IP addresses are not supported")
        if self.observable_classification == self.ObservableTypes.URL:
            target_observable = urlparse(self.observable_name).hostname
        params = {"q": target_observable}

        # convert root parameter into 1 or 0
        if self.root:
            params["root"] = int(self.root)

        # pass list of fuzzy parameter
        if self.fuzzy:
            params["fuzzy"] = self.fuzzy

        # convert dates to correct format
        if hasattr(self, "from_date") and self.from_date:
            params["from"] = self.convert_date_type(self.from_date)

        if hasattr(self, "to_date") and self.to_date:
            params["to"] = self.convert_date_type(self.to_date)

        if hasattr(self, "not_before") and self.not_before:
            params["not_before"] = self.convert_date_type(self.not_before)

        if self.sort:
            params["sort"] = self.sort

        if self.format:
            params["format"] = self.format

        if self.limit:
            params["limit"] = self.limit

        if self.offset:
            params["offset"] = self.offset

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
