# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models import Q

from api_app.choices import TLP


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(
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
    ).update(maximum_tlp=TLP.CLEAR.value)

    AnalyzerConfig.objects.filter(
        python_module__in=["firehol_iplist.FireHol_IPList", "talos.Talos", "tor.Tor"]
    ).update(maximum_tlp=TLP.RED.value)

    AnalyzerConfig.objects.filter(
        python_module__in=["triage.triage_search.TriageSearch"]
    ).filter(maximum_tlp=TLP.AMBER.value)

    new_config = AnalyzerConfig.objects.get(name="UnpacMe_EXE_Unpacker")
    new_config.name = "UnpacMe"
    new_config.save()
    old_config = AnalyzerConfig.objects.get(name="UnpacMe_EXE_Unpacker")
    for param in old_config.parameters.all():
        param.analyzer_config = new_config
        param.save()
    for visualizer in old_config.visualizers.all():
        visualizer.analyzers.remove(old_config)
        visualizer.analyzers.add(new_config)
        visualizer.save()
    for playbook in old_config.playbooks.all():
        playbook.analyzers.remove(old_config)
        playbook.analyzers.add(new_config)
        playbook.save()
    for job in old_config.requested_in_jobs.all():
        job.analyzers_requested.remove(old_config)
        job.analyzers_requested.add(new_config)
        job.save()
    for job in old_config.executed_in_jobs.all():
        job.analyzers_to_execute.remove(old_config)
        job.analyzers_to_execute.add(new_config)
        job.save()

    old_config.delete()

    new_config = AnalyzerConfig.objects.get(name="BoxJS_Scan_JavaScript")
    new_config.name = "BoxJS"
    new_config.save()
    old_config = AnalyzerConfig.objects.get(name="BoxJS_Scan_JavaScript")
    for param in old_config.parameters.all():
        param.analyzer_config = new_config
        param.save()
    for visualizer in old_config.visualizers.all():
        visualizer.analyzers.remove(old_config)
        visualizer.analyzers.add(new_config)
        visualizer.save()
    for playbook in old_config.playbooks.all():
        playbook.analyzers.remove(old_config)
        playbook.analyzers.add(new_config)
        playbook.save()
    for job in old_config.requested_in_jobs.all():
        job.analyzers_requested.remove(old_config)
        job.analyzers_requested.add(new_config)
        job.save()
    for job in old_config.executed_in_jobs.all():
        job.analyzers_to_execute.remove(old_config)
        job.analyzers_to_execute.add(new_config)
        job.save()
    old_config.delete()

    AnalyzerConfig.objects.filter(
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
    ).delete()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(
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
    ).update(maximum_tlp=TLP.GREEN.value)
    AnalyzerConfig.objects.filter(
        python_module__in=[
            "dragonfly.DragonflyEmulation",
            "filescan.FileScanUpload",
            "firehol_iplist.FireHol_IPList",
            "malpedia_scan.MalpediaScan",
            "talos.Talos",
            "tor.Tor",
        ]
    ).update(maximum_tlp=TLP.AMBER.value)
    AnalyzerConfig.objects.filter(python_module="sublime.Sublime").update(
        maximum_tlp=TLP.RED.value
    )
    config = AnalyzerConfig.objects.get(name="UnpacMe")
    config.name = "UnpacMe_EXE_Unpacker"
    new_config = config.save()
    old_config = AnalyzerConfig.objects.get(name="UnpacMe")
    for param in old_config.parameters.all():
        param.analyzer_config = new_config
        param.save()
    for visualizer in old_config.visualizers.all():
        visualizer.analyzers.remove(old_config)
        visualizer.analyzers.add(new_config)
    for playbook in old_config.playbooks.all():
        playbook.analyzers.remove(old_config)
        playbook.analyzers.add(new_config)
    old_config.delete()
    config = AnalyzerConfig.objects.get(name="BoxJS")
    config.name = "BoxJS_Scan_JavaScript"
    new_config = config.save()
    old_config = AnalyzerConfig.objects.get(name="BoxJS")
    for param in old_config.parameters.all():
        param.analyzer_config = new_config
        param.save()
    for visualizer in old_config.visualizers.all():
        visualizer.analyzers.remove(old_config)
        visualizer.analyzers.add(new_config)
    for playbook in old_config.playbooks.all():
        playbook.analyzers.remove(old_config)
        playbook.analyzers.add(new_config)
    old_config.delete()


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
