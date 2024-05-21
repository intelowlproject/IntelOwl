from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="phoneinfoga_scan.Phoneinfoga",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    Parameter.objects.create(
        name="googlecse_max_results",
        type="int",
        description="Number of Google results for [Phoneinfoga](https://sundowndev.github.io/phoneinfoga/)",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    p2 = Parameter.objects.create(
        name="scanners",
        type="list",
        description="List of scanner names for [Phoneinfoga](https://sundowndev.github.io/phoneinfoga/). Available options are: `local,numverify,googlecse,ovh`",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    p3 = Parameter.objects.get(name="scanner_name", python_module=pm)
    for config in pm.analyzerconfigs.all():
        pcs = PluginConfig.objects.filter(analyzer_config=config, parameter=p3)
        for pc in pcs:
            pc.value = [pc.value]
            pc.parameter = p2
            pc.save()
    p3.delete()
    Parameter.objects.create(
        name="all_scanners",
        type="bool",
        description="Set this to True to enable all available scanners. "
        "If enabled, this overwrite the scanner param",
        is_secret=False,
        required=False,
        python_module=pm,
    )


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("analyzers_manager", "0087_alter_mmdbserver_param"),
    ]

    operations = [migrations.RunPython(migrate, migrations.RunPython.noop)]
