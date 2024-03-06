from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "VirusTotal_v3_Intelligence_Search",
    "python_module": {
        "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "perform an advanced query through VirusTotal Intelligence. This is a premium feature only",
    "disabled": False,
    "soft_time_limit": 30,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
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
            "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "limit",
        "type": "int",
        "description": "max number of results to retrieve",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "order_by",
        "type": "str",
        "description": "More information in VT [docs](https://developers.virustotal.com/reference/intelligence-search) ",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "API Key for the analyzer. You need to have a premium license with VT.",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "limit",
            "type": "int",
            "description": "max number of results to retrieve",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 300,
        "updated_at": "2024-02-09T10:52:20.510902Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Intelligence_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_intelligence_search.VirusTotalv3Intelligence",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "order_by",
            "type": "str",
            "description": "More information in VT [docs](https://developers.virustotal.com/reference/intelligence-search) ",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:20.522599Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Intelligence_Search",
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
        ("analyzers_manager", "0002_0131_analyzer_config_virustotal_v3_get_observable"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
