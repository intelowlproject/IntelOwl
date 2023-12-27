from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "DNS0_rrsets_data",
    "python_module": {
        "module": "dns0.dns0_rrsets.DNS0Rrsets",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Query billions of current and historical DNS resource records sets. [API](https://docs.dns0.eu/dns-api/rrsets).",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": ["url", "domain", "generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "name": "direction",
        "type": "str",
        "description": "Used to dispatch matching direction.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "api_key",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "type",
        "type": "list",
        "description": "Limit results to certain record types (e.g. type=NS,A,AAAA). Accepts a comma-separated list of DNS record types, either in textual or numeric form.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "from",
        "type": "str",
        "description": "Limit results to records seen after this date.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "to",
        "type": "str",
        "description": "Limit results to records seen before this date.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "not_before",
        "type": "str",
        "description": "Limit results to records not seen before this date.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "sort",
        "type": "str",
        "description": "Available sorts are first_seen (the default) or last_seen. Both are descending sorts (most recent first).",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "format",
        "type": "str",
        "description": "Available formats are json, cof or dig. Default format is based on the Accept HTTP header.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "limit",
        "type": "int",
        "description": "Limit the number of results.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
    {
        "name": "offset",
        "type": "int",
        "description": "Used for pagination.",
        "is_secret": False,
        "required": False,
        "python_module": {
            "module": "dns0.dns0_rrsets.DNS0Rrsets",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
    },
]

values = [
    {
        "for_organization": False,
        "value": "right",
        "updated_at": "2023-12-13T15:29:41.780158Z",
        "owner": None,
        "parameter": {
            "name": "direction",
            "type": "str",
            "description": "Used to dispatch matching direction.",
            "is_secret": False,
            "required": False,
            "python_module": {
                "module": "dns0.dns0_rrsets.DNS0Rrsets",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
        },
        "analyzer_config": "DNS0_rrsets_data",
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
        ("api_app", "0051_pythonmodule_health_check_schedule_and_more"),
        ("analyzers_manager", "0052_analyzer_config_dns0_names"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
