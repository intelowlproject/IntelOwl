from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.suricata import Suricata

from .base_test_class import BaseFileAnalyzerTest


class TestSuricata(BaseFileAnalyzerTest):
    analyzer_class = Suricata

    def get_extra_config(self):
        return {"reload_rules": True, "extended_logs": False, "signatures": {}}

    def get_mocked_response(self):
        # Mock Suricata analysis results with network alerts
        mock_suricata_report = {
            "data": [],
            "stats": {
                "capture": {"kernel_packets": 150, "kernel_drops": 0},
                "decoder": {
                    "pkts": 150,
                    "bytes": 45600,
                    "invalid": 0,
                    "ipv4": 148,
                    "ipv6": 2,
                    "ethernet": 150,
                    "tcp": 100,
                    "udp": 48,
                    "icmpv4": 2,
                },
            },
        }

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.suricata.Suricata._docker_run",
                return_value=mock_suricata_report,
            ),
        ]
