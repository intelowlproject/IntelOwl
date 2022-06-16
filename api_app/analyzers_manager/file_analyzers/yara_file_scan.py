# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.observable_analyzers.yara_search import YaraSearch
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class YaraFileScan(FileAnalyzer):
    def run(self):
        return self.before_file_scan(self.md5)

    def before_file_scan(self, hash):
        self.search_term = hash
        self.base_url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.query = "lookup_hash"
        self.__api_key = self._secrets["api_key_name"]

        data_ = {
            "query": self.query,
            "search_term": self.search_term,
            "malpedia-token": self.__api_key,
        }

        json_data = json.dumps(data_)
        response = requests.post(self.base_url, data=json_data)
        response.raise_for_status()
        result = response.json()

        return result

    def set_params(self, params):
        self.base_url: str = "https://yaraify-api.abuse.ch/api/v1/"
        self.__api_key = self._secrets["api_key_name"]

        self.clamav_scan = params.get("clamav_scan", 1)
        self.unpack = params.get("unpack", 0)
        self.share_file = params.get("share_file", 1)

        self.max_tries = 200
        self.poll_distance = 3

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockResponse({}, 200),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)


"""
    def run(self):
        name_to_send = self.filename if self.filename else self.md5
        file = self.read_file_bytes()

        #verificare l'hash del file con yara_search
        hash_scan = self.before_file_scan(self.md5)
        query_status = hash_scan.get("query_status")

        if query_status == 'ok':
            return {}

        data = {
            'clamav_scan': self.clamav_scan,
            'unpack': self.unpack,
            'identifier': self.__api_key
        }
        
        files_ = {
            'json_data': (None, json.dumps(data), 'application/json'),
            'file': (name_to_send, file)
        }

            
        logger.info(f"yara file scan md5 {self.md5} sending sample for analysis")
        for _try in range(self.max_tries):
            logger.info(f"yara file scan md5 {self.md5} polling for result try #{_try + 1}")
            response = requests.post(self.base_url, files=files_)
            if response.status_code == 200:
                break
            time.sleep(self.poll_distance)


        result = response.json()
        return result
"""
