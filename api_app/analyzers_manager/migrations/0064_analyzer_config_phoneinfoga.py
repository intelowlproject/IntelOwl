from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "module": "phoneinfoga_scan.Phoneinfoga",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "Phoneinfoga",
    "description": "[Phoneinfoga](https://sundowndev.github.io/phoneinfoga/)",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "GREEN",
    "observable_supported": ["generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "phoneinfoga_scan.Phoneinfoga",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "scanner_name",
        "type": "str",
        "description": "scanner name for phoneinfoga",
        "is_secret": False,
        "required": True,
    }
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "phoneinfoga_scan.Phoneinfoga",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "scanner_name",
            "type": "str",
            "description": "scanner name for phoneinfoga",
            "is_secret": False,
            "required": True,
        },
        "for_organization": False,
        "value": "local",
        "updated_at": "2024-01-31T15:36:24.678116Z",
        "owner": None,
        "analyzer_config": 152,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    }
]


def _get_real_obj(Model, field, value):
    if (
        type(getattr(Model, field))
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        # in case is a dictionary, we have to retrieve the object with every key
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            value = other_model.objects.get(pk=value)
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            value = _get_real_obj(Model, field, value)
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            attribute.set(value)


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    _create_object(Model, plugin)
    for param in params:
        _create_object(Parameter, param)
    for value in values:
        _create_object(PluginConfig, value)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0059_alter_organizationpluginconfiguration_unique_together"),
        (
            "analyzers_manager",
            "0063_alter_analyzerconfig_not_supported_filetypes_and_more",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
