from django.db import migrations

from api_app.analyzers_manager.constants import ObservableTypes


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    config = AnalyzerConfig.objects.get(name="DNS0_rrsets_data")
    config.observable_supported = [
        ObservableTypes.DOMAIN,
        ObservableTypes.GENERIC,
        ObservableTypes.IP,
    ]
    config.full_clean()
    config.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    config = AnalyzerConfig.objects.get(name="DNS0_rrsets_data")
    config.observable_supported = [
        ObservableTypes.DOMAIN,
        ObservableTypes.URL,
        ObservableTypes.GENERIC,
        ObservableTypes.IP,
    ]
    config.full_clean()
    config.save()


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0058_4_change_primary_key"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
