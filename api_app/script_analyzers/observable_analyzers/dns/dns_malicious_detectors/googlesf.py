"""Check if the domains is reported as malicious for GoogleSafeBrowsing"""

from pysafebrowsing import SafeBrowsing

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from api_app.script_analyzers.observable_analyzers.dns.dns_responses import (
    malicious_detector_response,
)
from intel_owl import secrets


class GoogleSF(classes.ObservableAnalyzer):
    """Check if observable analyzed is marked as malicious for Google SafeBrowsing"""

    def run(self):
        api_key_name = "GSF_KEY"
        api_key = secrets.get_secret(api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: '{api_key_name}'"
            )

        sb_instance = SafeBrowsing(api_key)
        response = sb_instance.lookup_urls([self.observable_name])
        if self.observable_name in response and isinstance(
            response[self.observable_name], dict
        ):
            malicious = response[self.observable_name]["malicious"]
        else:
            raise AnalyzerRunException(f"result not expected: {response}")

        return malicious_detector_response(self.observable_name, malicious)
