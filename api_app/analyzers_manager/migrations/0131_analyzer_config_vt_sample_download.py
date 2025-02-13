from django.db import migrations

from api_app.analyzers_manager.constants import TypeChoices
from api_app.choices import TLP


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.create(
        name="VirusTotalv3SampleDownload",
        description="Download sample from VT.",
        type=TypeChoices.OBSERVABLE.value,
        maximum_tlp=TLP.AMBER.value,
        python_module=PythonModule.objects.get(
            module="vt.vt3_sample_download.VirusTotalv3SampleDownload"
        ),
        observable_supported=["hash"],
    )


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    AnalyzerConfig.objects.get(name="VirusTotalv3SampleDownload").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("analyzers_manager", "0130_analyzer_config_nvd_cve"),
        ("api_app", "0064_vt_sample_download"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
