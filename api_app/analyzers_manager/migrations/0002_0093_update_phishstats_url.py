from django.db import migrations


def update_phishstats_url(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.filter(
        module="phishstats.PhishStats"
    ).update(
        config__url="https://api.phishstats.info/api/phishing"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0002_0092_analyzer_config_phishtank"),
    ]

    operations = [
        migrations.RunPython(update_phishstats_url),
    ]

