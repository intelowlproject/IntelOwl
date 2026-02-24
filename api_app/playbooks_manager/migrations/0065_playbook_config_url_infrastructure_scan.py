import datetime

from django.db import migrations

from api_app.choices import TLP


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")

    playbook, _ = PlaybookConfig.objects.get_or_create(
        name="URL_Infrastructure_Scan",
        defaults={
            "description": "Performs a comprehensive crawl analysis of a URL to identify "
            "related infrastructure, redirect chains, network requests, and hosting information. "
            "Useful for investigating phishing pages and their linked resources.",
            "disabled": False,
            "type": ["url", "domain"],
            "scan_mode": 2,
            "scan_check_time": datetime.timedelta(days=1),
            "tlp": TLP.AMBER.value,
            "starting": True,
        },
    )

    urlscan_submit = AnalyzerConfig.objects.get(name="UrlScan_Submit_Result")
    urlscan_search = AnalyzerConfig.objects.get(name="UrlScan_Search")
    playbook.analyzers.set([urlscan_submit, urlscan_search])
    playbook.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    PlaybookConfig.objects.get(name="URL_Infrastructure_Scan").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0001_2_initial_squashed"),
        ("playbooks_manager", "0064_add_machoinfo_to_sample_static_analysis"),
        ("analyzers_manager", "0177_update_urlscan_observable_supported"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
