# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious for GoogleSafeBrowsing"""

from pysafebrowsing import SafeBrowsing

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes
from api_app.analyzers_manager.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)


class GoogleSF(classes.ObservableAnalyzer):
    """Check if observable analyzed is marked as malicious for Google SafeBrowsing"""

    def run(self):
        api_key = self._secrets["api_key_name"]

        sb_instance = SafeBrowsing(api_key)
        response = sb_instance.lookup_urls([self.observable_name])
        if self.observable_name in response and isinstance(
            response[self.observable_name], dict
        ):
            result = response[self.observable_name]
        else:
            raise AnalyzerRunException(f"result not expected: {response}")

        malicious = result["malicious"]
        googlesb_result = malicious_detector_response(self.observable_name, malicious)
        # append google extra data
        if malicious:
            googlesb_result["cache"] = result["cache"]
            googlesb_result["threats"] = result["threats"]
            googlesb_result["platforms"] = result["platforms"]
        return googlesb_result
