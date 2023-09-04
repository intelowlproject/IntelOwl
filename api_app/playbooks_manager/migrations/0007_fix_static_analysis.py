# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample Static Analysis")
    pc.type = ["file"]
    pc.description = "Execute a static analysis"
    pc.disabled = False
    pc.analyzers.set(
        [
            "Rtf_Info",
            "APKiD",
            "Doc_Info",
            "ClamAV",
            "Cymru_Hash_Registry_Get_File",
            "OneNote_Info",
            "MalwareBazaar_Get_File",
            "YARAify_File_Search",
            "PDF_Info",
            "BoxJS",
            "HybridAnalysis_Get_File",
            "Yara",
            "OTX_Check_Hash",
            "Quark_Engine",
        ]
    )
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample Static Analysis")
    pc.analyzers.set([])
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0006_rename_static_analysis"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
