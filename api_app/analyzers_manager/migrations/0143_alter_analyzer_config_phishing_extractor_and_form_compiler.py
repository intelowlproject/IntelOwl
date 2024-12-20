from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm_extractor = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm_form_compiler = PythonModule.objects.get(
        module="phishing.phishing_form_compiler.PhishingFormCompiler",
        base_path="api_app.analyzers_manager.file_analyzers",
    )
    p_extractor = Parameter.objects.create(
        name="user_agent",
        type="str",
        description="Custom user agent for the Phishing Extractor Selenium browser.",
        is_secret=False,
        required=False,
        python_module=pm_extractor,
    )
    p_form_compiler = Parameter.objects.create(
        name="user_agent",
        type="str",
        description="Custom user agent for the compilation of form.",
        is_secret=False,
        required=False,
        python_module=pm_form_compiler,
    )
    for config in pm_extractor.analyzerconfigs.all():
        PluginConfig.objects.create(
            parameter=p_extractor,
            analyzer_config=config,
            value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.3",
            owner=None,
            for_organization=False,
        )

    for config in pm_form_compiler.analyzerconfigs.all():
        PluginConfig.objects.create(
            parameter=p_form_compiler,
            analyzer_config=config,
            value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.3",
            owner=None,
            for_organization=False,
        )


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm_extractor = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm_form_compiler = PythonModule.objects.get(
        module="phishing.phishing_form_compiler.PhishingFormCompiler",
        base_path="api_app.analyzers_manager.file_analyzers",
    )

    p_extractor = Parameter.objects.get(
        name="user_agent",
        type="str",
        description="Custom user agent for the Phishing Extractor Selenium browser.",
        is_secret=False,
        required=False,
        python_module=pm_extractor,
    )
    p_form_compiler = Parameter.objects.get(
        name="user_agent",
        type="str",
        description="Custom user agent for the compilation of form",
        is_secret=False,
        required=False,
        python_module=pm_form_compiler,
    )

    for config in pm_extractor.analyzerconfigs.all():
        PluginConfig.objects.create(
            parameter=p_extractor,
            analyzer_config=config,
        )

    for config in pm_form_compiler.analyzerconfigs.all():
        PluginConfig.objects.create(
            parameter=p_form_compiler,
            analyzer_config=config,
        )

    p_extractor.delete()
    p_form_compiler.delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        (
            "analyzers_manager",
            "0142_alter_analyzerreport_data_model_content_type_and_more",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
