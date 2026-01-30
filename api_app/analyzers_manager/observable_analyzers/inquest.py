# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import re
from typing import Dict

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class InQuest(ObservableAnalyzer):
    url: str = "https://labs.inquest.net"

    _api_key_name: str
    inquest_analysis: str

    @classmethod
    def update(cls) -> bool:
        pass

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.generic_identifier_mode = "user-defined"  # Or auto

    @property
    def hash_type(self):
        hash_lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
        hash_type = hash_lengths.get(len(self.observable_name))
        if not hash_type:
            raise AnalyzerRunException(
                f"Given Hash: '{self.observable_name}' is not supported. "
                "Supported hash types are: 'md5', 'sha1', 'sha256', 'sha512'."
            )
        return hash_type

    def type_of_generic(self):
        if re.match(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", self.observable_name):
            type_ = "email"
        else:
            # TODO: This should be validated more thoroughly
            type_ = "filename"
        return type_

    def run(self):
        headers = {"Content-Type": "application/json"}
        # optional API key
        if hasattr(self, "_api_key_name"):
            headers["Authorization"] = self._api_key_name
        else:
            warning = "No API key retrieved"
            logger.info(f"{warning}. Continuing without API key... <- {self.__repr__()}")
            self.report.errors.append(warning)

        if self.inquest_analysis == "dfi_search":
            link = "dfi"
            if self.observable_classification == Classification.HASH:
                uri = f"/api/dfi/search/hash/{self.hash_type}?hash={self.observable_name}"

            elif self.observable_classification in [
                Classification.IP,
                Classification.URL,
                Classification.DOMAIN,
            ]:
                uri = f"/api/dfi/search/ioc/{self.observable_classification}?keyword={self.observable_name}"

            elif self.observable_classification == Classification.GENERIC:
                try:
                    type_, value = self.observable_name.split(":")
                except ValueError:
                    self.generic_identifier_mode = "auto"
                    type_ = self.type_of_generic()
                    value = self.observable_name

                if type_ not in ["email", "filename", "registry", "xmpid"]:
                    raise AnalyzerRunException(f"Unknown Type: {type_}")

                uri = f"/api/dfi/search/ioc/{type_}?keyword={value}"
            else:
                raise AnalyzerRunException()

        elif self.inquest_analysis == "iocdb_search":
            uri = f"/api/iocdb/search?keyword={self.observable_name}"
            link = "iocdb"

        elif self.inquest_analysis == "repdb_search":
            uri = f"/api/repdb/search?keyword={self.observable_name}"
            link = "repdb"

        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.inquest_analysis}' not supported."
                "Supported are: 'dfi_search', 'iocdb_search', 'repdb_search'."
            )

        response = requests.get(self.url + uri, headers=headers, timeout=30)
        response.raise_for_status()
        result = response.json()
        if self.inquest_analysis == "dfi_search" and self.observable_classification == Classification.HASH:
            result["hash_type"] = self.hash_type

        if self.generic_identifier_mode == "auto":
            result["type_of_generic"] = self.type_of_generic()

        result["link"] = f"https://labs.inquest.net/{link}"
        return result
