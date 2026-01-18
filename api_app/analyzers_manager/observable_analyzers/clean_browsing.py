# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64

import requests

from api_app.analyzers_manager.analyzers import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class CleanBrowsing(ObservableAnalyzer):
    BASE_URL = "https://doh.cleanbrowsing.org/doh/"

    def run(self):
        # 1. Get Configuration
        filter_type = self.configuration.get("filter_type", "family")

        # 2. Dynamic URL Construction (Maintainer Request)
        # Result: https://doh.cleanbrowsing.org/doh/family-filter/
        url = f"{self.BASE_URL}{filter_type}-filter/"

        # 3. Create DNS Packet
        binary_dns = self._create_dns_query(self.observable_name)
        # Remove padding '=' per DNS-over-HTTPS spec
        b64_payload = base64.urlsafe_b64encode(binary_dns).decode("utf-8").rstrip("=")

        try:
            headers = {"Accept": "application/dns-message"}
            params = {"dns": b64_payload}

            response = requests.get(url, params=params, headers=headers, timeout=10)

            # 4. Check Response
            # We treat any non-200 as a potential error or failure
            if response.status_code != 200:
                raise AnalyzerRunException(
                    f"CleanBrowsing API returned status {response.status_code}"
                )

            is_blocked = self._check_if_blocked(response.content)

            # 5. Return Result
            return {
                "filter_used": filter_type,
                "status": "blocked" if is_blocked else "allowed",
                "status_code": response.status_code,
                "raw_response_length": len(response.content),
            }

        except requests.exceptions.RequestException as e:
            raise AnalyzerRunException(f"Connection to CleanBrowsing failed: {e}")

    @staticmethod
    def _create_dns_query(domain):
        """
        Manually builds a raw DNS query packet (RFC 1035).
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
        Parses the binary DNS header to check the RCODE.
        RCODE 3 = NXDOMAIN (Blocked).
        """
        if not binary_response or len(binary_response) < 4:
            return False

        # RCODE is in the last 4 bits of the 4th byte (Index 3)
        # 0x83 -> 1000 0011 -> RCODE 3
        rcode = binary_response[3] & 0x0F

        return rcode == 3

    @classmethod
    def _get_scanner_parameters(cls):
        return [
            {
                "name": "filter_type",
                "type": "str",
                "description": "Choose family, adult, or security.",
                "required": False,
                "default": "family",
                "choices": ["family", "adult", "security"],
            }
        ]
