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
    dependencies = (("analyzers_manager", "0149_alter_die_analyzer"),)

    operations = [
        migrations.RunPython(update_maximum_tlp, reverse_update_maximum_tlp),
    ]
