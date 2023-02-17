# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Check if the domains is reported as malicious for GoogleSafeBrowsing"""

from pysafebrowsing import SafeBrowsing

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

from ..dns_responses import malicious_detector_response


class GoogleSF(classes.ObservableAnalyzer):
    """Check if observable analyzed is marked as malicious for Google SafeBrowsing"""

    def set_params(self, params):
        # so `observable_name` is available inside `_monkeypatch` method
        # as `cls.observable_name`
        self.__class__.observable_name = self.observable_name

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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(
                    SafeBrowsing,
                    "lookup_urls",
                    return_value={
                        cls.observable_name: {
                            "malicious": True,
                            "cache": "test",
                            "threats": "test",
                            "platforms": "test",
                        }
                    },
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
