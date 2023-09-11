# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations


def migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample_Static_Analysis")
    pc.analyzers.set(
        [
            "File_Info",
            "PE_Info",
            "ELF_Info",
            "Strings_Info",
            "HashLookupServer_Get_File",
            "Yara",
            "HybridAnalysis_Get_File",
            "Doc_Info",
            "Xlm_Macro_Deobfuscator",
            "Capa_Info",
            "PDF_Info",
            "Rtf_Info",
            "OTX_Check_Hash",
            "MalwareBazaar_Get_File",
            "BoxJS",
            "Cymru_Hash_Registry_Get_File",
            "ClamAV",
            "YARAify_File_Search",
            "APKiD",
            "OneNote_Info",
            "Signature_Info",
            "Floss",
            "Quark_Engine",
        ]
    )
    pc.full_clean()
    pc.save()


def reverse_migrate(apps, schema_editor):
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    pc = PlaybookConfig.objects.get(name="Sample_Static_Analysis")
    pc.analyzers.set(
        [
            "Rtf_Info",
            "APKiD",
            "Doc_Info",
            "ClamAV",
            "OneNote_Info",
            "PE_Info",
            "Signature_Info",
            "PDF_Info",
            "BoxJS",
            "HybridAnalysis_Get_File",
            "Yara",
            "Quark_Engine",
            "Capa_Info",
            "ELF_Info",
            "File_Info",
            "Floss",
            "Strings_Info",
            "Xlm_Macro_Deobfuscator",
        ]
    )
    pc.full_clean()
    pc.save()


class Migration(migrations.Migration):
    dependencies = [
        ("playbooks_manager", "0018_playbookconfig_scan_check_time_and_more"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
