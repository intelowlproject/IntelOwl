from django.db import migrations

from api_app.choices import PythonModuleBasePaths


def migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")

    # analyzer python module
    vt_sample_analyzer_python_module, _ = PythonModule.objects.get_or_create(
        module="vt.vt3_sample_download.VirusTotalv3SampleDownload",
        base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
    )

    # visualizer python module
    vt_sample_visualizer_python_module, _ = PythonModule.objects.get_or_create(
        module="sample_download.SampleDownload",
        base_path=PythonModuleBasePaths.Visualizer.value,
    )

    # analyzer parameter
    try:
        Parameter.objects.get(
            name="api_key_name", python_module=vt_sample_analyzer_python_module
        )
    except Parameter.DoesNotExist:
        p = Parameter(
            name="api_key_name",
            type="str",
            description="VT API key",
            is_secret=True,
            required=True,
            python_module=vt_sample_analyzer_python_module,
        )
        p.full_clean()
        p.save()


def reverse_migrate(apps, schema_editor):
    PythonModule = apps.get_model("api_app", "PythonModule")

    vt_sample_analyzer_python_module = PythonModule.objects.get(
        module="vt.vt3_sample_download.VirusTotalv3SampleDownload"
    )
    print(f"{vt_sample_analyzer_python_module.connectorconfigs.all()=}")
    vt_sample_analyzer_python_module.delete()
    vt_sample_visualizer_python_module = PythonModule.objects.get(
        module="sample_download.SampleDownload"
    )
    vt_sample_visualizer_python_module.delete()


class Migration(migrations.Migration):

    dependencies = [
        ("api_app", "0063_singleton_and_elastic_report"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
