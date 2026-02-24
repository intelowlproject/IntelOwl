# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import pathlib
from pathlib import PosixPath

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import Classification
from api_app.decorators import classproperty
from api_app.mixins import VirusTotalv3AnalyzerMixin, VirusTotalv3BaseMixin
from tests import CustomTestCase
from tests.mock_utils import MockUpResponse

possible_responses = {
    "_vt_get_iocs_from_file": MockUpResponse(
        {
            "data": {
                "id": "b665290bc6bba034a69c32f54862518a86a2dab93787a7e99daaa552c708b23a",
                "type": "file",
                "links": {"self": "redacted"},
                "attributes": {},
                "relationships": {
                    "contacted_urls": {
                        "data": [
                            {
                                "type": "url",
                                "id": "b33ca60c36a2dbdb354936f83e3232ae886eeb237f61bfdd19420410f585c0c2",
                                "context_attributes": {
                                    "url": "http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt"
                                },
                            },
                            {
                                "type": "url",
                                "id": "e1deefc8a4613fe9c16014d5cce4de4a6e12f3caccf80838a04c82faa4b42434",
                                "context_attributes": {
                                    "url": "http://pki.goog/gsr1/gsr1.crt"
                                },
                            },
                        ],
                        "links": {"self": "redacted", "related": "redacted"},
                    },
                    "contacted_domains": {
                        "data": [
                            {"type": "domain", "id": "microsoft.com"},
                            {"type": "domain", "id": "pki.goog"},
                        ],
                        "links": {"self": "redacted", "related": "redacted"},
                    },
                    "contacted_ips": {
                        "data": [
                            {"type": "ip_address", "id": "108.177.119.113"},
                            {"type": "ip_address", "id": "108.177.96.113"},
                            {"type": "ip_address", "id": "146.75.118.172"},
                            {"type": "ip_address", "id": "162.125.1.18"},
                        ],
                        "links": {"self": "redacted", "related": "redacted"},
                    },
                },
            }
        },
        200,
    ),
}


class VirusTotalv3Base(VirusTotalv3BaseMixin):
    @classproperty
    def python_base_path(cls) -> PosixPath:
        return pathlib.PosixPath(r"/")

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> dict:
        return {}


class VirusTotalv3Analyzer(VirusTotalv3AnalyzerMixin):
    @classproperty
    def python_base_path(cls) -> PosixPath:
        return pathlib.PosixPath(r"/")

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> dict:
        return {}


class VirusTotalMixinTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.base = VirusTotalv3Base()
        self.analyzer_file = VirusTotalv3Analyzer(
            AnalyzerConfig.objects.get(name="VirusTotal_v3_Get_File")
        )
        self.analyzer_observable = VirusTotalv3Analyzer(
            AnalyzerConfig.objects.get(name="VirusTotal_v3_Get_Observable")
        )

        self.base.url = self.analyzer_file.url = self.analyzer_observable.url = (
            "https://www.virustotal.com/api/v3/"
        )
        self._api_key_name = self._api_key_name = "123456"

    def test_get_requests_params_and_uri(self):
        expected_relationships = [
            "communicating_files",
            "historical_whois",
            "referrer_files",
            "resolutions",
            "siblings",
            "subdomains",
            "collections",
            "historical_ssl_certificates",
        ]
        params, uri, relationships_requested = self.base._get_requests_params_and_uri(
            Classification.DOMAIN, "google.com", True
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
        self.assertEqual(uri, "domains/google.com")

        expected_relationships = [
            "communicating_files",
            "historical_whois",
            "referrer_files",
            "resolutions",
            "collections",
            "historical_ssl_certificates",
        ]
        params, uri, relationships_requested = self.base._get_requests_params_and_uri(
            Classification.IP, "8.8.8.8", True
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
        self.assertEqual(uri, "ip_addresses/8.8.8.8")

        expected_relationships = [
            "last_serving_ip_address",
            "collections",
            "network_location",
        ]
        params, uri, relationships_requested = self.base._get_requests_params_and_uri(
            Classification.URL, "https://google.com/robots.txt", True
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
        self.assertEqual(uri, "urls/aHR0cHM6Ly9nb29nbGUuY29tL3JvYm90cy50eHQ")

        expected_relationships = [
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
        ]
        params, uri, relationships_requested = self.base._get_requests_params_and_uri(
            Classification.HASH, "5f423b7772a80f77438407c8b78ff305", True
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
        self.assertEqual(uri, "files/5f423b7772a80f77438407c8b78ff305")

        expected_relationships = [
            "behaviours",
            "bundled_files",
            "comments",
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "execution_parents",
            "pe_resource_parents",
            "votes",
            "distributors",
            "pe_resource_children",
            "dropped_files",
            "collections",
        ]
        params, uri, relationships_requested = self.base._get_requests_params_and_uri(
            Classification.HASH, "5f423b7772a80f77438407c8b78ff305", False
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
