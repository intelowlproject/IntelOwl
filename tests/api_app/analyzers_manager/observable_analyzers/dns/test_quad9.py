# This file is a part of IntelOwl
# https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

import pytest

from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.quad9_malicious_detector import (
    Quad9MaliciousDetector,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.quad9_dns_resolver import (
    Quad9DNSResolver,
)

# =========================
# Quad9 DNS Resolver Tests
# =========================


@pytest.mark.django_db
@patch("httpx.Client.get")
def test_quad9_dns_resolver_handles_non_utf8_json(mock_get):
    """
    Quad9DNSResolver should gracefully handle non-UTF8 / invalid JSON
    and return an empty resolutions list instead of crashing.
    """
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = ValueError("Invalid UTF-8")
    mock_get.return_value = mock_response

    # Create analyzer instance with required config
    analyzer = Quad9DNSResolver(config={})
    analyzer.observable_name = "example.com"
    analyzer.observable_classification = "domain"
    analyzer.headers = {}

    with patch.object(
        analyzer, "convert_to_domain", return_value="example.com"
    ), patch.object(
        analyzer,
        "build_query_url",
        return_value="https://dns.quad9.net/dns-query?name=example.com",
    ):

        result = analyzer.run()

        assert result["observable"] == "example.com"
        assert result["resolutions"] == []


@pytest.mark.django_db
@patch("httpx.Client.get")
def test_quad9_dns_resolver_extracts_addresses(mock_get):
    """
    Quad9DNSResolver should correctly extract DNS resolutions
    from a valid JSON response.
    """
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "Answer": [
            {"data": "1.1.1.1"},
            {"data": "8.8.8.8"},
        ]
    }
    mock_get.return_value = mock_response

    analyzer = Quad9DNSResolver(config={})
    analyzer.observable_name = "example.com"
    analyzer.observable_classification = "domain"
    analyzer.headers = {}

    with patch.object(
        analyzer, "convert_to_domain", return_value="example.com"
    ), patch.object(
        analyzer,
        "build_query_url",
        return_value="https://dns.quad9.net/dns-query?name=example.com",
    ):

        result = analyzer.run()

        assert sorted(result["resolutions"]) == ["1.1.1.1", "8.8.8.8"]


# =================================
# Quad9 Malicious Detector Tests
# =================================


@pytest.mark.django_db
@patch("dns.message.from_wire")
@patch("httpx.Client.get")
@patch("requests.get")
def test_quad9_malicious_detector_detects_malicious_domain(
    mock_google_get,
    mock_quad9_get,
    mock_from_wire,
):
    """
    Domain is malicious when:
    - Quad9 returns NO DNS answers
    - Google DNS returns an answer
    """
    # Quad9 DNS response - empty answers
    mock_dns_message = MagicMock()
    mock_dns_message.answer = []
    mock_from_wire.return_value = mock_dns_message

    quad9_response = MagicMock()
    quad9_response.raise_for_status.return_value = None
    quad9_response.content = b"\x00\x01\x02"
    mock_quad9_get.return_value = quad9_response

    # Google DNS response - has Answer
    google_response = MagicMock()
    google_response.raise_for_status.return_value = None
    google_response.json.return_value = {"Answer": [{"data": "1.2.3.4"}]}
    mock_google_get.return_value = google_response

    detector = Quad9MaliciousDetector(config={})
    detector.observable_name = "malicious.com"
    detector.observable_classification = "domain"
    detector.headers = {}

    with patch.object(
        detector, "convert_to_domain", return_value="malicious.com"
    ), patch.object(
        detector,
        "build_query_url",
        return_value="https://dns.quad9.net/dns-query?name=malicious.com",
    ):

        result = detector.run()

        assert result["observable"] == "malicious.com"
        assert result["malicious"] is True


@pytest.mark.django_db
@patch("dns.message.from_wire")
@patch("httpx.Client.get")
def test_quad9_malicious_detector_not_malicious_when_quad9_answers(
    mock_quad9_get,
    mock_from_wire,
):
    """
    Domain is NOT malicious when Quad9 returns DNS answers.
    Google DNS must not be queried.
    """
    # Quad9 DNS response - has an answer
    record = MagicMock()
    record.address = "1.1.1.1"

    answer = MagicMock()
    answer.__iter__.return_value = [record]

    mock_dns_message = MagicMock()
    mock_dns_message.answer = [answer]
    mock_from_wire.return_value = mock_dns_message

    quad9_response = MagicMock()
    quad9_response.raise_for_status.return_value = None
    quad9_response.content = b"\x00\x01\x02"
    mock_quad9_get.return_value = quad9_response

    detector = Quad9MaliciousDetector(config={})
    detector.observable_name = "safe.com"
    detector.observable_classification = "domain"
    detector.headers = {}

    with patch.object(
        detector, "convert_to_domain", return_value="safe.com"
    ), patch.object(
        detector,
        "build_query_url",
        return_value="https://dns.quad9.net/dns-query?name=safe.com",
    ):

        result = detector.run()

        assert result["observable"] == "safe.com"
        assert result["malicious"] is False
