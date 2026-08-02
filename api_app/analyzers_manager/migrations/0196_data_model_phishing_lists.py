# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

# Same declarative pattern as 0195: $-prefixed keys are written as literal
# constants (analyzers_manager/models.py:92-95). A listing hit is gated in each
# analyzer's _do_create_data_model, so a miss produces no data model.
MAPPINGS = {
    "PhishingArmy": {"$malicious": "evaluation", "$6": "reliability"},
    "Phishstats": {"$malicious": "evaluation", "$6": "reliability"},
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
        ("analyzers_manager", "0195_data_model_key_free_detectors"),
    ]
    operations = [
        migrations.RunPython(apply_mappings, revert_mappings),
    ]
