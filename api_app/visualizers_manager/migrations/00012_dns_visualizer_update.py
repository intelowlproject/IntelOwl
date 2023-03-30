# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

analyzers_list = [
    "Classic_DNS",
    "CloudFlare_DNS",
    "DNS0_EU",
    "Google_DNS",
    "Quad9_DNS",
    "CloudFlare_Malicious_Detector",
    "DNS0_EU_Malicious_Detector",
    "GoogleSafebrowsing",
    "GoogleWebRisk",
    "Quad9_Malicious_Detector",
]


def update_dns_visualizer(apps, schema_editor):
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    analyzers = AnalyzerConfig.objects.filter(name__in=analyzers_list)
    print(f"{analyzers_list=}")
    print(f"all analyzers: {AnalyzerConfig.objects.all()}")
    print(f"filtered analyzers: {analyzers}")
    vc = VisualizerConfig.objects.get(name="DNS")
    vc.analyzers.set(analyzers)


class Migration(migrations.Migration):

    dependencies = [
        ("visualizers_manager", "00011_dns_visualizer"),
    ]

    operations = [
        migrations.RunPython(update_dns_visualizer),
    ]
