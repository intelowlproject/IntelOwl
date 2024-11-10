import re

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import AnalyzerRunException, ObservableAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class NVDDetails(ObservableAnalyzer):
    url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _nvd_api_key: str = None
    cve_pattern = r"^CVE-\d{4}-\d{4,7}$"

    @classmethod
    def update(self) -> bool:
        pass

    def run(self):
        headers = {}
        if self._nvd_api_key:
            headers.update({"apiKey": self._nvd_api_key})

        try:
            # Validate if CVE format is correct E.g CVE-2014-1234 or cve-2022-1234567
            if not settings.STAGE_CI and not re.match(
                self.cve_pattern, self.observable_name, flags=re.IGNORECASE
            ):
                raise ValueError(f"Invalid CVE format: {self.observable_name}")

            params = {"cveId": self.observable_name.upper()}
            response = requests.get(url=self.url, params=params, headers=headers)
            response.raise_for_status()

        except ValueError as e:
            raise AnalyzerRunException(e)
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "resultsPerPage": 1,
                            "startIndex": 0,
                            "totalResults": 1,
                            "format": "NVD_CVE",
                            "version": "2.0",
                            "timestamp": "2024-11-01T05:25:09.787",
                            "vulnerabilities": [
                                {
                                    "cve": {
                                        "id": "CVE-2024-51181",
                                        "sourceIdentifier": "cve@mitre.org",
                                        "published": "2024-10-29T13:15:07.297",
                                        "lastModified": "2024-10-29T20:35:37.490",
                                        "vulnStatus": "Undergoing Analysis",
                                        "cveTags": [],
                                        "descriptions": [
                                            {
                                                "lang": "en",
                                                "value": "A Reflected Cross Site Scripting (XSS) vulnerability was found"
                                                "in /ifscfinder/admin/profile.php in PHPGurukul IFSC Code Finder"
                                                "Project v1.0, which allows remote attackers to execute arbitrary"
                                                'code via " searchifsccode" parameter.',
                                            },
                                            {
                                                "lang": "es",
                                                "value": " Se encontró una vulnerabilidad de Cross Site Scripting reflejado"
                                                "(XSS) en /ifscfinder/admin/profile.php en PHPGurukul IFSC Code Finder"
                                                "Project v1.0, que permite a atacantes remotos ejecutar código arbitrario"
                                                'a través del parámetro "searchifsccode".',
                                            },
                                        ],
                                        "metrics": {
                                            "cvssMetricV31": [
                                                {
                                                    "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                                                    "type": "Secondary",
                                                    "cvssData": {
                                                        "version": "3.1",
                                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L",
                                                        "attackVector": "NETWORK",
                                                        "attackComplexity": "LOW",
                                                        "privilegesRequired": "NONE",
                                                        "userInteraction": "REQUIRED",
                                                        "scope": "CHANGED",
                                                        "confidentialityImpact": "HIGH",
                                                        "integrityImpact": "LOW",
                                                        "availabilityImpact": "LOW",
                                                        "baseScore": 8.8,
                                                        "baseSeverity": "HIGH",
                                                    },
                                                    "exploitabilityScore": 2.8,
                                                    "impactScore": 5.3,
                                                }
                                            ]
                                        },
                                        "weaknesses": [
                                            {
                                                "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                                                "type": "Secondary",
                                                "description": [
                                                    {
                                                        "lang": "en",
                                                        "value": "CWE-79",
                                                    }
                                                ],
                                            }
                                        ],
                                        "references": [
                                            {
                                                "url": "https://github.com/Santoshcyber1/CVE-wirteup/blob/main/"
                                                "Phpgurukul/IFSC%20Code%20Finder/IFSC%20Code%20Finder%20Admin.pdf",
                                                "source": "cve@mitre.org",
                                            }
                                        ],
                                    }
                                }
                            ],
                        },
                        200,
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
