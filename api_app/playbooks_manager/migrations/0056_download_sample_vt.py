import datetime

from django.db import migrations

from api_app.choices import TLP


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    playbook_download_sample_vt, _ = PlaybookConfig.objects.get_or_create(
        name="Download_File_VT",
        description="Download a sample from VT",
        type=["hash"],
        tlp=TLP.AMBER.value,
        scan_check_time=datetime.timedelta(days=14),
    )
    vt_download_file_analyzer = AnalyzerConfig.objects.get(
        name="VirusTotalv3SampleDownload"
    )
    playbook_download_sample_vt.analyzers.set([vt_download_file_analyzer])
    playbook_download_sample_vt.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    PlaybookConfig.objects.get(name="Download_File_VT").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks_manager", "0055_playbook_config_phishingextractor"),
        ("analyzers_manager", "0131_analyzer_config_vt_sample_download"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
