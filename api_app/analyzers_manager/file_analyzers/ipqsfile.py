# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""IPQualityScore file analyzer.

Provides `IPQSFileScan`, a file-scanning analyzer that uploads files to
IPQualityScore for malware detection and polls for results.
"""

import logging

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.mixins import IPQualityScoreMixin

logger = logging.getLogger(__name__)


class IPQSFileScan(FileAnalyzer, IPQualityScoreMixin):
    """
    Scan a binary file using IPQualityScore malware detection service.
    """

    @classmethod
    def update(cls):
        pass

    def run(self):
        binary = self.read_file_bytes()
        files = {"files": (self.filename, binary)}
        # lookup endpoint check for cached result
        lookup_result = self._make_request(
            self.lookup_endpoint,
            method="POST",
            _api_key=self._ipqs_api_key,
            files=files,
        )
        if lookup_result.get("status", False) == "cached":
            lookup_result.pop("update_url", None)
            return lookup_result
        # sending file to ipqs for scan
        scan_result = self._make_request(
            self.scan_endpoint,
            method="POST",
            _api_key=self._ipqs_api_key,
            files=files,
        )
        # waiting for scan result with help of request id
        result = self._poll_for_report(
            endpoint=self.postback_endpoint,
            _api_key=self._ipqs_api_key,
            request_id=scan_result.get("request_id"),
        )
        result.pop("update_url", None)
        return result
