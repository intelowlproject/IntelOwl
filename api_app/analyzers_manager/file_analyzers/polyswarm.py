# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json
import logging

from polyswarm_api.api import PolyswarmAPI

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Polyswarm(FileAnalyzer):
    # this class also acts as a super class
    #  for PolyswarmObs in observable analyzers
    url = "https://api.polyswarm.network/v3"
    _api_key: str = None
    timeout: int = 60 * 15  # default as in the package settings
    polyswarm_community: str = "default"

    @staticmethod
    def construct_result(result):
        res = {"assertions": []}
        positives = 0
        total = 0
        for assertion in result.assertions:
            if assertion.verdict:
                positives += 1
            total += 1
            res["assertions"].append(
                {
                    "engine": assertion.author_name,
                    "asserts": "Malicious" if assertion.verdict else "Benign",
                }
            )
        res["positives"] = positives
        res["total"] = total
        res["PolyScore"] = result.polyscore
        res["sha256"] = result.sha256
        res["md5"] = result.md5
        res["sha1"] = result.sha1
        res["extended_type"] = result.extended_type
        res["first_seen"] = result.first_seen.isoformat()
        res["last_seen"] = result.last_seen.isoformat()
        res["permalink"] = result.permalink
        return res

    def run(self):
        api = PolyswarmAPI(key=self._api_key, community=self.polyswarm_community)
        instance = api.submit(self.filepath)
        result = api.wait_for(instance, timeout=self.timeout)
        if result.failed:
            raise AnalyzerRunException(
                f"Failed to get results from Polyswarm for {self.md5}"
            )
        result = self.construct_result(result)

        return result

    def update(self):
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(
                    Polyswarm,
                    "run",
                    # flake8: noqa
                    return_value={
                        "assertions": [
                            {"engine": "Kaspersky", "asserts": "Benign"},
                            {"engine": "Qihoo 360", "asserts": "Benign"},
                            {"engine": "XVirus", "asserts": "Benign"},
                            {"engine": "SecureAge", "asserts": "Benign"},
                            {"engine": "DrWeb", "asserts": "Benign"},
                            {"engine": "Proton", "asserts": "Benign"},
                            {"engine": "Electron", "asserts": "Benign"},
                            {"engine": "Filseclab", "asserts": "Benign"},
                            {"engine": "ClamAV", "asserts": "Benign"},
                            {"engine": "SecondWrite", "asserts": "Benign"},
                            {"engine": "Ikarus", "asserts": "Benign"},
                            {"engine": "NanoAV", "asserts": "Benign"},
                            {"engine": "Alibaba", "asserts": "Benign"},
                        ],
                        "positives": 0,
                        "total": 13,
                        "PolyScore": 0.33460048640798623,
                        "sha256": "50f4d8be8d47d26ecb04f1a24f17a39f3ea194d8cdc3b833aef2df88e1ce828b",
                        "md5": "76deca20806c16df50ffeda163fd50e9",
                        "sha1": "99ff1cd17aea94feb355e7bdb01e9f788a4971bb",
                        "extended_type": "GIF image data, version 89a, 821 x 500",
                        "first_seen": "2024-07-27T20:20:12.121980",
                        "last_seen": "2024-07-27T20:20:12.121980",
                        "permalink": "https://polyswarm.network/scan/results/file/50f4d8be8d47d26ecb04f1a24f17a39f3ea194d8cdc3b833aef2df88e1ce828b/76218824984622961",
                    },
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
