import re
from abc import ABCMeta
from logging import getLogger

import dateparser

from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)

_supported_sort_types = [
    "first_seen",
    "last_seen",
]

_min_limit_value = 0
_max_limit_value = 50000

_min_offset_value = 0

logger = getLogger(__name__)


class DNS0Mixin(BaseAnalyzerMixin, metaclass=ABCMeta):
    base_url: str = "https://api.dns0.eu/"

    _api_key: str
    from_date: str
    to_date: str
    not_before: str
    sort: str
    format: str
    limit: int
    offset: int

    def _create_headers(self):
        headers = {
            "Accept": "application/json",
        }
        if hasattr(self, "_api_key") and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    @staticmethod
    def convert_date_type(date_string):
        if not date_string:
            return False

        date_parsed = (
            DNS0Mixin.convert_unix_timestamp(date_string)
            or DNS0Mixin.convert_relative_date(date_string)
            or DNS0Mixin.convert_date(date_string)
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

    def _validate_params(self):
        if hasattr(self, "sort") and self.sort not in _supported_sort_types:
            raise AnalyzerConfigurationException(
                f"Sort type {self.sort} not supported! "
                f"Available sort types are: {_supported_sort_types}"
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

    def _create_params(self):
        params = dict()
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
