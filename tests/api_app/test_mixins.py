# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from pathlib import PosixPath

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.ingestors_manager.models import IngestorConfig
from api_app.mixins import VirusTotalv3AnalyzerMixin, VirusTotalv3BaseMixin
from tests import CustomTestCase


class VirusTotalv3Base(VirusTotalv3BaseMixin):
    @classmethod
    def python_base_path(cls) -> PosixPath:
        pass

    def run(self) -> dict:
        return {}


class VirusTotalv3Analyzer(VirusTotalv3AnalyzerMixin):
    @classmethod
    def python_base_path(cls) -> PosixPath:
        pass

    def run(self) -> dict:
        return {}


class VirusTotalMixinTestCase(CustomTestCase):
    def setUp(self) -> None:
        self.base = VirusTotalv3Base(
            IngestorConfig.objects.get(name="VirusTotal_Example_Query")
        )
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
            ObservableTypes.DOMAIN, "google.com", True
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
            ObservableTypes.IP, "8.8.8.8", True
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
            ObservableTypes.URL, "https://google.com/robots.txt", True
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
            ObservableTypes.HASH, "5f423b7772a80f77438407c8b78ff305", True
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
            ObservableTypes.HASH, "5f423b7772a80f77438407c8b78ff305", False
        )
        self.assertIn("relationships", params)
        self.assertListEqual(relationships_requested, expected_relationships)
        self.assertEqual(params["relationships"], ",".join(expected_relationships))
