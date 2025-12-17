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

    # Updated to include ALL 3 free filters
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

    def run(self):
        target_domain = self.observable_name
        filter_type = self.config.get("filter_type", "family")

        # Select the correct URL based on the user's choice
        if filter_type == "security":
            url = "https://doh.cleanbrowsing.org/doh/security-filter/"
        elif filter_type == "adult":
            url = "https://doh.cleanbrowsing.org/doh/adult-filter/"
        else:
            # Default to Family (Strictest)
            url = "https://doh.cleanbrowsing.org/doh/family-filter/"

        binary_dns = self._create_dns_query(target_domain)
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

    def _create_dns_query(self, domain):
        # Header: ID=0, Flags=0x0100 (Standard Query), QDCOUNT=1
        packet = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

        parts = domain.split(".")
        for part in parts:
            packet += bytes([len(part)]) + part.encode("utf-8")
        packet += b"\x00"

        packet += b"\x00\x01\x00\x01"
        return packet

    def _check_if_blocked(self, binary_response):
        """
        Parses the binary DNS header to check the RCODE (Response Code).
        RCODE 3 = NXDOMAIN (Domain does not exist), which is how CleanBrowsing blocks content.
        """
        if not binary_response or len(binary_response) < 12:
            return False
        rcode = binary_response[3] & 0x0F
        if rcode == 3:
            return True
        return False
