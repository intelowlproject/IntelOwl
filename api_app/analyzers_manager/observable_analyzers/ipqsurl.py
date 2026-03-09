"""IPQualityScore URL analyzer.

Provides `IPQSUrlScan`, an observable analyzer that scans URLs via
the IPQualityScore service and polls for results.
"""

import logging

from api_app.analyzers_manager import classes
from api_app.mixins import IPQualityScoreMixin

logger = logging.getLogger(__name__)


class IPQSUrlScan(classes.ObservableAnalyzer, IPQualityScoreMixin):
    """
    Scan a URL using IPQualityScore service.
    """

    @classmethod
    def update(cls):
        pass

    def run(self):
        # lookup check for url results into ipqs database
        lookup_result = self._make_request(
            endpoint=self.lookup_endpoint,
            method="POST",
            _api_key=self._ipqs_api_key,
            data={"url": self.observable_name},
        )
        if lookup_result.get("status", False) == "cached":
            lookup_result.pop("update_url", None)
            return lookup_result

        # sending url for scan
        scan_result = self._make_request(
            endpoint=self.scan_endpoint,
            method="POST",
            _api_key=self._ipqs_api_key,
            data={"url": self.observable_name},
        )
        # waiting for results for with request id of scanned results
        result = self._poll_for_report(
            endpoint=self.postback_endpoint,
            _api_key=self._ipqs_api_key,
            request_id=scan_result.get("request_id"),
        )
        result.pop("update_url", None)
        return result
