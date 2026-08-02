# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

# Single reviewable reliability table. $-prefixed keys are written as literal
# constants (analyzers_manager/models.py:92-95). Conditionality lives in each
# analyzer's _do_create_data_model gate, so a non-hit produces no data model.
# Reliability tiers reflect source authority: Google Safe Browsing/WebRisk (8)
# and Spamhaus (7) rank above the DNS-resolver blocklists (6).
MAPPINGS = {
    "GoogleSafebrowsing": {"$malicious": "evaluation", "$8": "reliability"},
    "GoogleWebRisk": {"$malicious": "evaluation", "$8": "reliability"},
    "Spamhaus_WQS": {"$malicious": "evaluation", "$7": "reliability"},
    "AdGuard": {"$malicious": "evaluation", "$6": "reliability"},
    "Quad9_Malicious_Detector": {"$malicious": "evaluation", "$6": "reliability"},
    "CloudFlare_Malicious_Detector": {"$malicious": "evaluation", "$6": "reliability"},
    "CleanBrowsing_Malicious_Detector": {"$malicious": "evaluation", "$6": "reliability"},
    "UltraDNS_Malicious_Detector": {"$malicious": "evaluation", "$6": "reliability"},
    "DNS4EU_Malicious_Detector": {"$malicious": "evaluation", "$6": "reliability"},
    "Mullvad_DNS": {"$malicious": "evaluation", "$6": "reliability"},
}


def apply_mappings(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for name, mapping in MAPPINGS.items():
        ac = AnalyzerConfig.objects.filter(name=name).first()
        if not ac:
            continue
        ac.mapping_data_model = mapping
        ac.save()


def revert_mappings(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for name in MAPPINGS:
        ac = AnalyzerConfig.objects.filter(name=name).first()
        if not ac:
            continue
        ac.mapping_data_model = {}
        ac.save()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0194_analyzer_config_rdap"),
    ]
    operations = [
        migrations.RunPython(apply_mappings, revert_mappings),
    ]
