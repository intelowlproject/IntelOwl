from django.db import migrations


def update_maximum_tlp(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    try:
        obj = AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector")
        obj.maximum_tlp = "CLEAR"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="DNS0_EU_Malicious_Detector")
        obj.maximum_tlp = "CLEAR"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="Quad9_Malicious_Detector")
        obj.maximum_tlp = "CLEAR"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="CloudFlare_Malicious_Detector")
        obj.maximum_tlp = "CLEAR"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass


def reverse_update_maximum_tlp(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    try:
        obj = AnalyzerConfig.objects.get(name="UltraDNS_Malicious_Detector")
        obj.maximum_tlp = "AMBER"  # Reverting to the original value
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="DNS0_EU_Malicious_Detector")
        obj.maximum_tlp = "AMBER"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="Quad9_Malicious_Detector")
        obj.maximum_tlp = "AMBER"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass

    try:
        obj = AnalyzerConfig.objects.get(name="CloudFlare_Malicious_Detector")
        obj.maximum_tlp = "AMBER"
        obj.save()
    except AnalyzerConfig.DoesNotExist:
        pass


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0145_analyzer_config_ultradns_malicious_detector"),
        ("analyzers_manager", "0002_0026_analyzer_config_dns0_eu_malicious_detector"),
        ("analyzers_manager", "0002_0099_analyzer_config_quad9_malicious_detector"),
        (
            "analyzers_manager",
            "0002_0019_analyzer_config_cloudflare_malicious_detector",
        ),
    ]
    operations = [
        migrations.RunPython(update_maximum_tlp, reverse_update_maximum_tlp),
    ]
