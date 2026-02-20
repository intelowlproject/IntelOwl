from django.db import migrations


def add_unprotect_url(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")

    try:
        pc = Parameter.objects.get(name="yara_rules_sources")
    except Parameter.DoesNotExist:
        return

    if pc.value is None:
        pc.value = []

    unprotect_url = "https://unprotect.it/api/detection_rules/"

    if unprotect_url not in pc.value:
        pc.value.append(unprotect_url)
        pc.save()


class Migration(migrations.Migration):

    dependencies = [
        ('analyzers_manager', '0176_analyzer_config_macho_info'),
    ]

    operations = [
        migrations.RunPython(add_unprotect_url),
    ]
