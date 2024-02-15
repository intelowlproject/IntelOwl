from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Anomali_Threatstream",
    "python_module": {
        "module": "threatstream.Threatstream",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Analyzer to interact with Anomali ThreatStream APIs",
    "disabled": False,
    "soft_time_limit": 30,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
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
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "minimal_confidence",
        "type": "str",
        "description": "Minimal Confidence filter",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "limit",
        "type": "str",
        "description": "Number of maximal entries returned",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "threatstream_analysis",
        "type": "str",
        "description": "API endpoint called: options are `confidence`, `intelligence` and `passive_dns`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "modified_after",
        "type": "str",
        "description": "Filter on entries modified after a specific date. Date must be specified in this format: YYYYMMDDThhmmss where T denotes the start of the value for time, in UTC time. For example, 2014-10-02T20:44:35.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "must_active",
        "type": "bool",
        "description": "Only return active entries",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_user_name",
        "type": "str",
        "description": "API USER for Anomali Threatstream",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "threatstream.Threatstream",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "API Key for Anomali Threatstream",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "threatstream.Threatstream",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "minimal_confidence",
            "type": "str",
            "description": "Minimal Confidence filter",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "0",
        "updated_at": "2024-02-09T10:52:21.892899Z",
        "owner": None,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "threatstream.Threatstream",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "limit",
            "type": "str",
            "description": "Number of maximal entries returned",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "100",
        "updated_at": "2024-02-09T10:52:21.812344Z",
        "owner": None,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "threatstream.Threatstream",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "threatstream_analysis",
            "type": "str",
            "description": "API endpoint called: options are `confidence`, `intelligence` and `passive_dns`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "intelligence",
        "updated_at": "2024-02-09T10:52:21.855528Z",
        "owner": None,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "threatstream.Threatstream",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "modified_after",
            "type": "str",
            "description": "Filter on entries modified after a specific date. Date must be specified in this format: YYYYMMDDThhmmss where T denotes the start of the value for time, in UTC time. For example, 2014-10-02T20:44:35.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "1900-10-02T20:44:35",
        "updated_at": "2024-02-09T10:52:21.947784Z",
        "owner": None,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "threatstream.Threatstream",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "must_active",
            "type": "bool",
            "description": "Only return active entries",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:22.000752Z",
        "owner": None,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
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
        return False
    return True


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    if not Model.objects.filter(name=plugin["name"]).exists():
        exists = _create_object(Model, plugin)
        if not exists:
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
        ("api_app", "0001_2_initial_squashed"),
        ("analyzers_manager", "0002_0001_analyzer_config_abuseipdb"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
