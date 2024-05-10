from django.db import migrations


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    ac = AnalyzerConfig.objects.get(
        name="Doc_Info",
    )
    ac.supported_filetypes.remove("application/onenote")
    ac.save()


def reverse_migrate(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0082_analyzer_config_ip2whois"),
    ]
    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
