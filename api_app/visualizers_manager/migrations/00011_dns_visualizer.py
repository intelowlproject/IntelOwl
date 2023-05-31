# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

visualizers = {
    "DNS": {
        "disabled": False,
        "description": "Visualize information about DNS resolvers "
                       "and DNS malicious detectors",
        "python_module": "dns.DNS",
        "analyzers": [
            "Classic_DNS",
            "CloudFlare_DNS",
            "DNS0_EU",
            "Google_DNS",
            "Quad9_DNS",
            "CloudFlare_Malicious_Detector",
            "DNS0_EU_Malicious_Detector",
            "GoogleSafebrowsing",
            "GoogleWebRisk",
            "Quad9_Malicious_Detector", ],
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


def reverse_dns_visualizer(apps, schema_editor):
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    VisualizerConfig.objects.get(name="DNS").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("visualizers_manager", "00010_remove_runtime_configuration"),
    ]

    operations = [
        migrations.RunPython(create_configurations, reverse_dns_visualizer),
    ]
