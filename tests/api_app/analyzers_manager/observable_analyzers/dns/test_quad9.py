# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

import dns.message

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.quad9_malicious_detector import (
    Quad9MaliciousDetector,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.quad9_dns_resolver import (
    Quad9DNSResolver,
)
from tests import CustomTestCase


class Quad9DNSResolverTestCase(CustomTestCase):
    """Test cases for Quad9DNSResolver"""

    @patch("httpx.Client.get")
    def test_handles_dns_error(self, mock_get):
        """
        Quad9DNSResolver should gracefully handle DNS parsing errors
        and return an empty resolutions list instead of crashing.
        """
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"\x00\x01"
        mock_get.return_value = mock_response

        analyzer = Quad9DNSResolver(config={})
        analyzer.observable_name = "example.com"
        analyzer.observable_classification = "domain"

        with (
            patch.object(analyzer, "convert_to_domain", return_value="example.com"),
            patch.object(
                analyzer,
                "build_query_url",
                return_value="https://dns.quad9.net/dns-query?dns=example",
            ),
            self.assertRaises(dns.message.ShortHeader),
        ):
            analyzer.run()

    @patch("dns.message.from_wire")
    @patch("httpx.Client.get")
    def test_extracts_addresses(self, mock_get, mock_from_wire):
        """
        Quad9DNSResolver should correctly extract DNS resolutions
        from wire format response.
        """
        record1 = MagicMock()
        record1.address = "1.1.1.1"

        record2 = MagicMock()
        record2.address = "8.8.8.8"

        answer = MagicMock()
        answer.__iter__.return_value = [record1, record2]

        mock_dns_message = MagicMock()
        mock_dns_message.answer = [answer]
        mock_from_wire.return_value = mock_dns_message

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"\x00\x01\x02\x03"
        mock_get.return_value = mock_response

        analyzer = Quad9DNSResolver(config={})
        analyzer.observable_name = "example.com"
        analyzer.observable_classification = "domain"

        with (
            patch.object(analyzer, "convert_to_domain", return_value="example.com"),
            patch.object(
                analyzer,
                "build_query_url",
                return_value="https://dns.quad9.net/dns-query?dns=example",
            ),
        ):
            result = analyzer.run()
            self.assertCountEqual(result["resolutions"], ["1.1.1.1", "8.8.8.8"])


class Quad9MaliciousDetectorTestCase(CustomTestCase):
    """Test cases for Quad9MaliciousDetector"""

    @patch("dns.message.from_wire")
    @patch("httpx.Client.get")
    @patch("requests.get")
    def test_detects_malicious_domain(self, mock_google_get, mock_quad9_get, mock_from_wire):
        """
        Domain is malicious when:
        - Quad9 returns NO DNS answers
        - Google DNS returns an answer
        """
        mock_dns_message = MagicMock()
        mock_dns_message.answer = []
        mock_from_wire.return_value = mock_dns_message

        quad9_response = MagicMock()
        quad9_response.raise_for_status.return_value = None
        quad9_response.content = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        mock_quad9_get.return_value = quad9_response

        google_response = MagicMock()
        google_response.raise_for_status.return_value = None
        google_response.json.return_value = {"Answer": [{"data": "1.2.3.4"}]}
        mock_google_get.return_value = google_response

        detector = Quad9MaliciousDetector(config={})
        detector.observable_name = "malicious.com"
        detector.observable_classification = "domain"

        with (
            patch.object(detector, "convert_to_domain", return_value="malicious.com"),
            patch.object(
                detector,
                "build_query_url",
                return_value="https://dns.quad9.net/dns-query?dns=malicious",
            ),
        ):
            result = detector.run()
            self.assertEqual(result["observable"], "malicious.com")
            self.assertTrue(result["malicious"])

    @patch("dns.message.from_wire")
    @patch("httpx.Client.get")
    def test_not_malicious_when_quad9_answers(self, mock_quad9_get, mock_from_wire):
        """
        Domain is NOT malicious when Quad9 returns DNS answers.
        Google DNS must not be queried.
        """
        record = MagicMock()
        record.address = "1.1.1.1"

        answer = MagicMock()
        answer.__iter__.return_value = [record]

        mock_dns_message = MagicMock()
        mock_dns_message.answer = [answer]
        mock_from_wire.return_value = mock_dns_message

        quad9_response = MagicMock()
        quad9_response.raise_for_status.return_value = None
        quad9_response.content = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        mock_quad9_get.return_value = quad9_response

        detector = Quad9MaliciousDetector(config={})
        detector.observable_name = "safe.com"
        detector.observable_classification = "domain"

        with (
            patch.object(detector, "convert_to_domain", return_value="safe.com"),
            patch.object(
                detector,
                "build_query_url",
                return_value="https://dns.quad9.net/dns-query?dns=safe",
            ),
        ):
            result = detector.run()
            self.assertEqual(result["observable"], "safe.com")
            self.assertFalse(result["malicious"])
