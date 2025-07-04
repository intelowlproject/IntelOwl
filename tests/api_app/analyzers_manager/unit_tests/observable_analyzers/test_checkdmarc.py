import json
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.observable_analyzers.checkdmarc import CheckDMARC
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class CheckDMARCTestCase(BaseAnalyzerTest):
    analyzer_class = CheckDMARC

    @staticmethod
    def get_mocked_response():
        mock_dmarc_response = {
            "domain": "example.com",
            "base_domain": "example.com",
            "dnssec": True,
            "ns": {"hostnames": ["ns1.example.com", "ns2.example.com"], "warnings": []},
            "mx": {
                "hosts": [
                    {
                        "hostname": "mail.example.com",
                        "preference": 10,
                        "addresses": ["192.168.1.10"],
                        "starttls": True,
                        "tls": True,
                    }
                ],
                "warnings": [],
            },
            "spf": {
                "record": "v=spf1 include:_spf.example.com ~all",
                "valid": True,
                "dns_lookups": 2,
                "warnings": [],
            },
            "dmarc": {
                "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                "valid": True,
                "location": "example.com",
                "warnings": [],
                "tags": {
                    "v": {"value": "DMARC1", "explicit": True},
                    "p": {"value": "quarantine", "explicit": True},
                    "rua": {"value": ["mailto:dmarc@example.com"], "explicit": True},
                },
            },
        }

        # Mock subprocess.Popen
        mock_process = MagicMock()
        mock_process.communicate.return_value = (
            json.dumps(mock_dmarc_response).encode("utf-8"),
            b"",
        )
        mock_process.wait.return_value = 0

        return [
            patch("shutil.which", return_value="/usr/bin/checkdmarc"),
            patch("subprocess.Popen", return_value=mock_process),
        ]
