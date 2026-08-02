# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.models import AnalyzerConfig
from tests import CustomTestCase


class DataModelTargetsAntiRotTestCase(CustomTestCase):
    MAPPED = {
        "GoogleSafebrowsing": 8,
        "GoogleWebRisk": 8,
        "Spamhaus_WQS": 7,
        "AdGuard": 6,
        "Quad9_Malicious_Detector": 6,
        "CloudFlare_Malicious_Detector": 6,
        "CleanBrowsing_Malicious_Detector": 6,
        "UltraDNS_Malicious_Detector": 6,
        "DNS4EU_Malicious_Detector": 6,
        "Mullvad_DNS": 6,
        "PhishingArmy": 6,
        "Phishstats": 6,
    }
    HOOKED = ["Phishtank", "Tranco"]

    def test_mapped_configs_exist_with_expected_reliability(self):
        for name, reliability in self.MAPPED.items():
            config = AnalyzerConfig.objects.filter(name=name).first()
            self.assertIsNotNone(config, f"missing analyzer config: {name}")
            self.assertEqual(config.mapping_data_model.get("$malicious"), "evaluation", name)
            self.assertEqual(config.mapping_data_model.get(f"${reliability}"), "reliability", name)

    def test_hooked_configs_exist(self):
        for name in self.HOOKED:
            self.assertTrue(
                AnalyzerConfig.objects.filter(name=name).exists(),
                f"missing analyzer config: {name}",
            )
