# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from api_app.choices import Classification
from api_app.connectors_manager.connectors.stix2 import STIX2
from tests.api_app.connectors_manager.unit_tests.base_test_class import (
    BaseConnectorTest,
)


class STIX2ConnectorTestCase(BaseConnectorTest):
    connector_class = STIX2

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "tlp": "CLEAR",
            "_job_id": 51,
        }

    def _setup_connector(self):
        connector = super()._setup_connector()

        connector._job.tags = MagicMock()
        connector._job.tags.all.return_value.values_list.return_value = [
            "malicious",
            "c2",
        ]

        connector._job.analyzers_to_execute = MagicMock()
        connector._job.analyzers_to_execute.all.return_value.values_list.return_value = [
            "LeakIX",
            "VirusTotal",
        ]

        return connector

    def test_run_success_ip_bundle(self):
        """Verify that an IP observable produces a valid STIX 2.1 bundle with SCO and Indicator."""
        connector = self._setup_connector()
        bundle_dict = connector.run()

        self.assertEqual(bundle_dict["type"], "bundle")
        self.assertIn("objects", bundle_dict)

        objects = bundle_dict["objects"]
        types = [obj["type"] for obj in objects]

        self.assertIn("ipv4-addr", types)
        self.assertIn("indicator", types)

        ipv4_obj = next((obj for obj in objects if obj["type"] == "ipv4-addr"), None)
        self.assertIsNotNone(ipv4_obj)
        self.assertEqual(ipv4_obj["value"], connector.observable_value)

        indicator_obj = next((obj for obj in objects if obj["type"] == "indicator"), None)
        self.assertIsNotNone(indicator_obj)
        self.assertIn(connector.observable_value, indicator_obj["pattern"])
        self.assertEqual(indicator_obj["pattern_type"], "stix")

    def test_run_domain_bundle(self):
        """Verify that a Domain observable produces a valid domain-name SCO."""
        connector = self._setup_connector()
        connector._job.is_sample = False
        connector._job.analyzable.classification = Classification.DOMAIN
        connector._job.analyzable.name = "malicious-c2.example.com"

        bundle_dict = connector.run()
        objects = bundle_dict["objects"]
        types = [obj["type"] for obj in objects]

        self.assertIn("domain-name", types)
        domain_obj = next((obj for obj in objects if obj["type"] == "domain-name"), None)
        self.assertIsNotNone(domain_obj)
        self.assertEqual(domain_obj["value"], "malicious-c2.example.com")

    def test_run_with_malware_family(self):
        """Verify that if a malware family is present, a Malware SDO and Relationship are created."""
        connector = self._setup_connector()
        mock_dm = MagicMock()
        mock_dm.malware_family = "Emotet"
        mock_dm.evaluation = "malicious"
        mock_dm.kill_chain_phase = None
        mock_dm.reliability = None
        mock_dm.related_threats = []
        mock_dm.tags = []
        mock_dm.external_references = []

        with patch.object(STIX2, "_merged_data_model", mock_dm):
            bundle_dict = connector.run()

        objects = bundle_dict["objects"]
        types = [obj["type"] for obj in objects]

        self.assertIn("malware", types)
        self.assertIn("relationship", types)

        malware_obj = next((obj for obj in objects if obj["type"] == "malware"), None)
        self.assertIsNotNone(malware_obj)
        self.assertEqual(malware_obj["name"], "Emotet")

        rel_obj = next((obj for obj in objects if obj["type"] == "relationship"), None)
        self.assertIsNotNone(rel_obj)
        self.assertEqual(rel_obj["relationship_type"], "indicates")
