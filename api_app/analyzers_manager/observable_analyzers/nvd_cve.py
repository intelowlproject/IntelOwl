import re

import requests

from api_app.analyzers_manager.classes import AnalyzerRunException, ObservableAnalyzer


class NVDDetails(ObservableAnalyzer):
    url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _nvd_api_key: str = None
    cve_pattern = r"^CVE-\d{4}-\d{4,7}$"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {}
        if self._nvd_api_key:
            headers.update({"apiKey": self._nvd_api_key})

        try:
            # Validate if CVE format is correct E.g CVE-2014-1234 or cve-2022-1234567
            if not re.match(self.cve_pattern, self.observable_name, flags=re.IGNORECASE):
                raise ValueError(f"Invalid CVE format: {self.observable_name}")

            params = {"cveId": self.observable_name.upper()}
            response = requests.get(url=self.url, params=params, headers=headers)
            response.raise_for_status()

        except ValueError as e:
            raise AnalyzerRunException(e)
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
