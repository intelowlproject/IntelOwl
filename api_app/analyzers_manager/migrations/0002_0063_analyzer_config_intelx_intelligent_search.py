from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "IntelX_Intelligent_Search",
    "python_module": {
        "module": "intelx.IntelX",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Intelligent search against IntelX API",
    "disabled": False,
    "soft_time_limit": 45,
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
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "dateto",
        "type": "str",
        "description": "use this in combination with 'datefrom' to filter the query",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "timeout",
        "type": "int",
        "description": "",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "datefrom",
        "type": "str",
        "description": "use this in combination with 'dateto' to filter the query",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "max_tries",
        "type": "int",
        "description": "",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "query_type",
        "type": "str",
        "description": "Query Type. Choose between 'playbook' and 'intelligent'",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "rows_limit",
        "type": "int",
        "description": "max number of results to retrieve",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "poll_distance",
        "type": "int",
        "description": "",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "intelx.IntelX",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "dateto",
            "type": "str",
            "description": "use this in combination with 'datefrom' to filter the query",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:17.512269Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "timeout",
            "type": "int",
            "description": "",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 10,
        "updated_at": "2024-02-09T10:52:17.528099Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "datefrom",
            "type": "str",
            "description": "use this in combination with 'dateto' to filter the query",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:17.542050Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "max_tries",
            "type": "int",
            "description": "",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 10,
        "updated_at": "2024-02-09T10:52:17.559015Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "query_type",
            "type": "str",
            "description": "Query Type. Choose between 'playbook' and 'intelligent'",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "intelligent",
        "updated_at": "2024-02-09T10:52:17.573352Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "rows_limit",
            "type": "int",
            "description": "max number of results to retrieve",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 1000,
        "updated_at": "2024-02-09T10:52:17.587835Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "intelx.IntelX",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "poll_distance",
            "type": "int",
            "description": "",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 3,
        "updated_at": "2024-02-09T10:52:17.602356Z",
        "owner": None,
        "analyzer_config": "IntelX_Intelligent_Search",
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
        ("analyzers_manager", "0002_0062_analyzer_config_inquest_repdb"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
