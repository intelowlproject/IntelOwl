# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

from api_app.choices import TLP


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    Parameter.objects.filter(
        name="upload_file", python_module__module="intezer_scan.IntezerScan"
    ).delete()
    Parameter.objects.filter(
        name="upload_file", python_module__module="mwdb_scan.MWDB_Scan"
    ).delete()
    Parameter.objects.filter(
        name="force_scan", python_module__module="virushee.VirusheeFileUpload"
    ).delete()
    Parameter.objects.filter(
        name="send_file", python_module__module="yaraify_file_scan.YARAify_File_Scan"
    ).delete()

    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    virushee_analyzer = AnalyzerConfig.objects.get(name="Virushee_Upload_File")
    virushee_analyzer.name = "Virushee_Scan"
    virushee_analyzer.description = 'Check file hash for analysis on [Virushee API]("https://api.virushee.com/). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service.'
    virushee_analyzer.maximum_tlp = TLP.AMBER.value
    virushee_analyzer.full_clean()
    virushee_analyzer.save()
    AnalyzerConfig.objects.get(name="Virushee_Upload_File").delete()

    intezer_analyzer = AnalyzerConfig.objects.get(name="Intezer_Scan")
    intezer_analyzer.description = "Scan a file hash on Intezer. Register for a free community account [here](https://analyze.intezer.com/sign-in?utm_source=IntelOwl). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service."
    intezer_analyzer.maximum_tlp = TLP.AMBER.value
    intezer_analyzer.full_clean()
    intezer_analyzer.save()

    mwdb_scan = AnalyzerConfig.objects.get(name="MWDB_Scan")
    mwdb_scan.description = "Check a file hash against [MWDB by Cert Polska](https://mwdb.cert.pl/). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service."
    mwdb_scan.maximum_tlp = TLP.AMBER.value
    mwdb_scan.full_clean()
    mwdb_scan.save()

    yaraify_scan = AnalyzerConfig.objects.get(name="YARAify_File_Scan")
    yaraify_scan.description = "Scan a file against public and non-public YARA and ClamAV signatures in [YARAify service](https://yaraify.abuse.ch/). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service."
    yaraify_scan.maximum_tlp = TLP.AMBER.value
    yaraify_scan.full_clean()
    yaraify_scan.save()

    vt_get_file = AnalyzerConfig.objects.get(name="VirusTotal_v3_Get_File")
    vt_get_file.description = "Check file hash on [VirusTotal](https://www.virustotal.com/). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service."
    vt_get_file.disabled = False
    vt_get_file.maximum_tlp = TLP.AMBER.value
    vt_get_file.full_clean()
    vt_get_file.save()

    AnalyzerConfig.objects.get(name="VirusTotal_v3_Get_File_And_Scan").delete()
    AnalyzerConfig.objects.get(name="VirusTotal_v2_Scan_File").delete()
    AnalyzerConfig.objects.get(name="VirusTotal_v2_Get_File").delete()
    AnalyzerConfig.objects.get(name="VirusTotal_v2_Get_Observable").delete()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        (
            "analyzers_manager",
            "0047_vt_removed_force_active_scan",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
