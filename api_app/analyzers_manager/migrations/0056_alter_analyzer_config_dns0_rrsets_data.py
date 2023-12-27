from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

from api_app.analyzers_manager.constants import ObservableTypes


def migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    config = AnalyzerConfig.objects.get(name="DNS0_rrsets_data")
    config.observable_supported = [
        ObservableTypes.DOMAIN,
        ObservableTypes.URL,
        ObservableTypes.GENERIC,
        ObservableTypes.IP,
    ]
    config.full_clean()
    config.save()

    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    pm = PythonModule.objects.get(
        module="dns0.dns0_rrsets.DNS0Rrsets",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    p = Parameter(
        name="include_subdomain",
        type="bool",
        description="Search for subdomains.",
        is_secret=False,
        required=False,
        python_module=pm,
    )
    p.full_clean()
    p.save()


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")
    config = AnalyzerConfig.objects.get(name="DNS0_rrsets_data")
    config.observable_supported = [
        ObservableTypes.DOMAIN,
        ObservableTypes.URL,
        ObservableTypes.GENERIC,
    ]
    config.full_clean()
    config.save()

    PythonModule = apps.get_model("api_app", "PythonModule")
    Parameter = apps.get_model("api_app", "Parameter")
    pm = PythonModule.objects.get(
        module="dns0.dns0_rrsets.DNS0Rrsets",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    p = Parameter(name="include_subdomain", python_module=pm).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0052_periodic_task_bi"),
        ("analyzers_manager", "0055_analyzerreport_sent_to_bi"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
