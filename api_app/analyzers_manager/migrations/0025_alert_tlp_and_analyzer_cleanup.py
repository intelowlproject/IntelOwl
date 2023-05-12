# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models import Q

from api_app.choices import TLP


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(
        Q(
            python_module__in=[
                "cape_sandbox.CAPEsandbox",
                "docguard.DocGuardUpload",
                "dragonfly.DragonflyEmulation",
                "filescan.FileScanUpload",
                "intezer_scan.IntezerScan",
                "mwdb_scan.MWDB_Scan",
                "malpedia_scan.MalpediaScan",
                "sublime.Sublime",
                "triage_scan.TriageScanFile",
                "triage_scan.TriageScanFile",
                "unpac_me.UnpacMe",
                "vt.vt2_scan.VirusTotalv2ScanFile",
                "virushee.VirusheeFileUpload",
                "yaraify_file_scan.YARAifyFileScan",
            ]
        )
        | Q(name="VirusTotal_v3_Get_File_And_Scan")
    ):
        config.maximum_tlp = TLP.CLEAR
        config.full_clean()
        config.save()

    for config in AnalyzerConfig.objects.filter(
        python_module__in=["firehol_iplist.FireHol_IPList", "talos.Talos", "tor.Tor"]
    ):
        config.maximum_tlp = TLP.RED
        config.full_clean()
        config.save()

    for config in AnalyzerConfig.objects.filter(
        python_module__in=["triage.triage_search.TriageSearch"]
    ):
        config.maximum_tlp = TLP.AMBER
        config.full_clean()
        config.save()

    for config in AnalyzerConfig.objects.filter(name="UnpacMe_EXE_Unpacker"):
        config.name = "UnpacMe"
        config.full_clean()
        config.save()
    for config in AnalyzerConfig.objects.filter(name="BoxJS_Scan_JavaScript"):
        config.name = "Box_JS"
        config.full_clean()
        config.save()

    for config in AnalyzerConfig.objects.filter(
        Q(python_module="darksearch.DarkSearchQuery")
        | Q(
            name__in=[
                "Doc_Info_Experimental",
                "Securitytrails_Details",
                "Securitytrails_History_DNS",
                "Securitytrails_History_WHOIS",
                "Securitytrails_IP_Neighbours",
                "Securitytrails_Subdomains",
                "Securitytrails_Tags",
                "Strings_Info_Classic",
                "Strings_Info_ML",
                "Threatminer_PDNS",
                "Threatminer_Reports_Tagging",
                "Threatminer_Subdomains",
                "Anomali_Threatstream_Confidence",
                "Anomali_Threatstream_Intelligence",
                "Anomali_Threatstream_PassiveDNS",
            ]
        )
    ):
        config.delete()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    for config in AnalyzerConfig.objects.filter(
        Q(
            python_module__in=[
                "cape_sandbox.CAPEsandbox",
                "docguard.DocGuardUpload",
                "intezer_scan.IntezerScan",
                "mwdb_scan.MWDB_Scan",
                "firehol_iplist.FireHol_IPList",
                "triage_scan.TriageScanFile",
                "unpac_me.UnpacMe",
                "vt.vt2_scan.VirusTotalv2ScanFile",
                "virushee.VirusheeFileUpload",
                "yaraify_file_scan.YARAifyFileScan",
            ]
        )
        | Q(name="VirusTotal_v3_Get_File_And_Scan")
    ):
        config.maximum_tlp = TLP.GREEN
        config.full_clean()
        config.save()
    for config in AnalyzerConfig.objects.filter(
        python_module__in=[
            "dragonfly.DragonflyEmulation",
            "filescan.FileScanUpload",
            "firehol_iplist.FireHol_IPList",
            "malpedia_scan.MalpediaScan",
            "talos.Talos",
            "tor.Tor",
        ]
    ):
        config.maximum_tlp = TLP.AMBER
        config.full_clean()
        config.save()
    for config in AnalyzerConfig.objects.filter(python_module="sublime.Sublime"):
        config.maximum_tlp = TLP.RED
        config.full_clean()
        config.save()
    for config in AnalyzerConfig.objects.filter(name="UnpacMe"):
        config.name = "UnpacMe_EXE_Unpacker"
        config.full_clean()
        config.save()
    for config in AnalyzerConfig.objects.filter(name="BoxJS"):
        config.name = "BoxJS_Scan_JavaScript"
        config.full_clean()
        config.save()


class Migration(migrations.Migration):

    dependencies = [
        (
            "analyzers_manager",
            "0024_alter_analyzerconfig_not_supported_filetypes_and_more",
        ),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
