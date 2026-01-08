# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import pytest
from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.quad9_dns_resolver import Quad9DNSResolver


@pytest.mark.django_db
@patch("httpx.Client.get")
def test_quad9_dns_resolver_handles_non_utf8(mock_get):
    class MockResponse:
        content = b"\xd5\x00\x01"
        @staticmethod
        def raise_for_status(): pass
        @staticmethod
        def json():
            return {
                "Answer": [
                    {"data": "1.1.1.1"}

                ]
            }

    mock_get.return_value = MockResponse()

    analyzer = Quad9DNSResolver(
        observable_name="test.com",
        observable_classification="domain",
        config={} 
    )

    result = analyzer.run()
    assert "1.1.1.1" in result["resolutions"]
