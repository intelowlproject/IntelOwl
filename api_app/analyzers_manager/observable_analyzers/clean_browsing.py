# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests
from django.utils.translation import gettext_lazy as _

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class CleanBrowsing(ObservableAnalyzer):
    typename = "CleanBrowsing"
    observable_classification = "domain"

    # BEST PRACTICE: Define static URLs as constants here
    URL_FAMILY = "https://doh.cleanbrowsing.org/doh/family-filter/"
    URL_ADULT = "https://doh.cleanbrowsing.org/doh/adult-filter/"
    URL_SECURITY = "https://doh.cleanbrowsing.org/doh/security-filter/"

    configuration_options = {
        "filter_type": {
            "type": "string",
            "default": "family",
            "choices": ["family", "adult", "security"],
            "description": _(
                "Choose 'family' (strictest), 'adult' (blocks porn), or 'security' (malware only)."
            ),
        }
    }

    @classmethod
    def update(cls):
        """
        This analyzer uses a live API, so no local database update is required.
        """
        return False

    @classmethod
    def _monkeypatch(cls):
        """
        Mock the requests.get method to return a fake blocked response
        for internal health checks and mocked testing.
        """
        import unittest.mock

        # Create a fake response object
        mock_response = unittest.mock.MagicMock()
        mock_response.status_code = 200
        # This is the binary representation of a "Blocked" (NXDOMAIN) response
        # RCODE 3 is in the 4th byte (0x83 -> 1000 0011)
        mock_response.content = b"\x00\x00\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"

        return unittest.mock.patch(
            "api_app.analyzers_manager.observable_analyzers.CleanBrowsing.requests.get",
            return_value=mock_response,
        )

    def run(self):
        target_domain = self.observable_name
        filter_type = getattr(self, "filter_type", "family")

        # Cleaner logic using the constants
        if filter_type == "security":
            url = self.URL_SECURITY
        elif filter_type == "adult":
            url = self.URL_ADULT
        else:
            url = self.URL_FAMILY

        binary_dns = self._create_dns_query(target_domain)
        # Remove the padding '=' as per DNS-over-HTTPS spec
        b64_payload = base64.urlsafe_b64encode(binary_dns).decode("utf-8").rstrip("=")

        try:
            headers = {"Accept": "application/dns-message"}
            params = {"dns": b64_payload}

            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()

            return {
                "filter_used": filter_type,
                "status_code": response.status_code,
                "is_blocked": self._check_if_blocked(response.content),
                "raw_response_length": len(response.content),
            }

        except requests.exceptions.RequestException as e:
            raise AnalyzerRunException(f"Connection to CleanBrowsing failed: {e}")

    @staticmethod
    def _create_dns_query(domain):
        """
        Manually builds a raw DNS query packet.
        """
        # Header: ID=0, Flags=0x0100 (Standard Query), QDCOUNT=1
        packet = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

        parts = domain.split(".")
        for part in parts:
            packet += bytes([len(part)]) + part.encode("utf-8")
        packet += b"\x00"

        packet += b"\x00\x01\x00\x01"  # Type A, Class IN
        return packet

    @staticmethod
    def _check_if_blocked(binary_response):
        """
        Parses the binary DNS header to check the RCODE (Response Code).
        RCODE 3 = NXDOMAIN (Domain does not exist), which is how CleanBrowsing blocks content.
        """
        if not binary_response or len(binary_response) < 12:
            return False

        # RCODE is in the last 4 bits of the 4th byte (Index 3)
        rcode = binary_response[3] & 0x0F

        if rcode == 3:
            return True

        return False
