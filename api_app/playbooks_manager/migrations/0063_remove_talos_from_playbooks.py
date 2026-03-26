# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.db import migrations


def remove_talos_from_playbooks(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    try:
        talos_analyzer = AnalyzerConfig.objects.get(name="TalosReputation")
    except AnalyzerConfig.DoesNotExist:
        talos_analyzer = None

    if talos_analyzer is not None:
        for playbook in PlaybookConfig.objects.filter(analyzers=talos_analyzer):
            playbook.analyzers.remove(talos_analyzer)

    # Also scrub runtime_configuration if present
    for playbook in PlaybookConfig.objects.all():
        rc = playbook.runtime_configuration
        if isinstance(rc, dict) and "analyzers" in rc and "TalosReputation" in rc["analyzers"]:
            del rc["analyzers"]["TalosReputation"]
            playbook.runtime_configuration = rc
            playbook.full_clean()
            playbook.save(update_fields=["runtime_configuration"])


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0062_add_cleanbrowsing_to_free_to_use"),
        ("analyzers_manager", "0175_analyzer_config_cleanbrowsing_malicious_detector"),
    ]

    operations = [
        migrations.RunPython(
            remove_talos_from_playbooks, reverse_code=migrations.RunPython.noop
        ),
    ]
