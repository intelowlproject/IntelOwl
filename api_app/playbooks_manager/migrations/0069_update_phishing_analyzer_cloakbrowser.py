from django.db import migrations


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = Parameter.objects.get(
        name="phishing_engine",
        
        python_module=pm,
    )
    param.description=(
            "Browser engine used for phishing analysis. "
            'Accepted values: "selenium" (default, Selenium-Wire) '
            'or "playwright" (Playwright) or "cloakbrowser" (CloakBrowser). Both produce the same '
            "output schema."
    )
    param.full_clean()
    param.save()
def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="phishing.phishing_extractor.PhishingExtractor",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    param = Parameter.objects.get(
        name="phishing_engine",
        
        python_module=pm,
    )
    param.description=(
            "Browser engine used for phishing analysis. "
            'Accepted values: "selenium" (default, Selenium-Wire) '
            'or "playwright" (Playwright). Both produce the same '
            "output schema."
        )
    param.full_clean()
    param.save()

class Migration(migrations.Migration):
    atomic = False
    dependencies = [
    ("playbooks_manager", "0068_add_rdap_to_free_to_use"),
    ("analyzers_manager", "0181_analyzer_config_phishing_engine_param"),
]
    operations = [migrations.RunPython(migrate, reverse_migrate)]
