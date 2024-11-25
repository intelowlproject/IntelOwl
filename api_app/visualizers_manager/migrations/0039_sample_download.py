from django.db import migrations


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    PlaybookConfig = apps.get_model("playbooks_manager", "PlaybookConfig")
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")

    visualizer_download_sample, _ = VisualizerConfig.objects.get_or_create(
        name="Download_File",
        description="Download a sample",
        python_module=PythonModule.objects.get(module="sample_download.SampleDownload"),
    )
    visualizer_download_sample.playbooks.add(
        *PlaybookConfig.objects.filter(
            analyzers=AnalyzerConfig.objects.get(name="DownloadFileFromUri")
        ),
        *PlaybookConfig.objects.filter(
            analyzers=AnalyzerConfig.objects.get(name="VirusTotalv3SampleDownload")
        )
    )
    visualizer_download_sample.save()


def reverse_migrate(apps, schema_editor):
    VisualizerConfig = apps.get_model("visualizers_manager", "VisualizerConfig")
    VisualizerConfig.objects.get(name="Download_File").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("visualizers_manager", "0038_visualizer_config_passive_dns"),
        ("playbooks_manager", "0056_download_sample_vt"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
