# tests/analyzer_mocks.py

from unittest.mock import patch

# from api_app.analyzers_manager.observable_analyzers.mmdb_server import MmdbServer
from tests.mock_utils import MockUpResponse


def dns0_eu_malicious_detector():
    return patch(
        "requests.get",
        return_value=MockUpResponse(
            {"Answer": [{"data": "negative-caching.dns0.eu"}]}, 200
        ),
    )


def nvdcve_mock_patch():
    return patch(
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


def cloudflare_malicious_detector():
    return patch(
        "requests.get",
        return_value=MockUpResponse({"Answer": [{"data": "0.0.0.0"}]}, 200),
    )


# central registry of all patches
ANALYZER_PATCHES = {
    "nvd_cve": nvdcve_mock_patch,
    "dns0_eu": dns0_eu_malicious_detector,
    "cloudflare_malicious_detector": cloudflare_malicious_detector,
}
