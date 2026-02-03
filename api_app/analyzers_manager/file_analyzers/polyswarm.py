# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging

from polyswarm_api.api import PolyswarmAPI

from api_app.analyzers_manager.classes import BaseAnalyzerMixin, FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class PolyswarmBase(BaseAnalyzerMixin, metaclass=abc.ABCMeta):
    # this class also acts as a super class
    #  for PolyswarmObs in observable analyzers
    url = "https://api.polyswarm.network/v3"
    _api_key: str = None
    timeout: int = 60 * 15  # default as in the package settings
    polyswarm_community: str = "default"

    def update(self):
        pass

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


class Polyswarm(FileAnalyzer, PolyswarmBase):
    def run(self):
        api = PolyswarmAPI(key=self._api_key, community=self.polyswarm_community)
        instance = api.submit(self.filepath)
        result = api.wait_for(instance, timeout=self.timeout)
        if result.failed:
            raise AnalyzerRunException(f"Failed to get results from Polyswarm for {self.md5}")
        result = self.construct_result(result)

        return result
