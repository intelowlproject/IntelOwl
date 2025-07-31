# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import requests

from api_app.analyzers_manager import classes
from api_app.mixins import AbuseCHMixin

logger = logging.getLogger(__name__)


class MB_GET(AbuseCHMixin, classes.ObservableAnalyzer):
    url: str = "https://mb-api.abuse.ch/api/v1/"
    sample_url: str = "https://bazaar.abuse.ch/sample/"

    def update(self) -> bool:
        pass

    def run(self):
        return self.query_mb_api(
            observable_name=self.observable_name,
            headers=self.authentication_header,
        )

    @classmethod
    def query_mb_api(cls, observable_name: str, headers: dict = None) -> dict:
        """
        This is in a ``classmethod`` so it can be reused in ``MB_GOOGLE``.
        """
        post_data = {"query": "get_info", "hash": observable_name}

        if headers is None:
            headers = {}

        response = requests.post(cls.url, data=post_data, headers=headers)
        response.raise_for_status()

        result = response.json()
        result_data = result.get("data", [])
        if result_data and isinstance(result_data, list):
            sha256 = result_data[0].get("sha256_hash", "")
            if sha256:
                result["permalink"] = f"{cls.sample_url}{sha256}"

        return result
