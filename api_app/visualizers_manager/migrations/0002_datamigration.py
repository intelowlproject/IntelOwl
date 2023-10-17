# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

visualizers = {
    "Yara": {
        "disabled": False,
        "description": "Visualize information about yara matches",
        "python_module": "yara.Yara",
        "analyzers": ["Yara"],
        "connectors": [],
        "params": {},
        "secrets": {},
    }
}


def create_configurations(apps, schema_editor):
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    ConnectorConfig = apps.get_model("connectors_manager", "ConnectorConfig")
    for visualizer_name, visualizer in visualizers.items():
        analyzers = AnalyzerConfig.objects.filter(name__in=visualizer.pop("analyzers"))
        connectors = ConnectorConfig.objects.filter(
            name__in=visualizer.pop("connectors")
        )
        vc = VisualizerConfig(name=visualizer_name, **visualizer)
        vc.full_clean()
        vc.save()
        vc.analyzers.set(analyzers)
        vc.connectors.set(connectors)


def delete_configurations(apps, schema_editor):
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    VisualizerConfig.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ("visualizers_manager", "0001_initial"),
        ("analyzers_manager", "0004_datamigration"),
        ("connectors_manager", "0004_datamigration"),
    ]

    operations = [
        migrations.RunPython(create_configurations, delete_configurations),
    ]
