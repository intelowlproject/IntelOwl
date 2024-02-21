from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "MISP",
    "python_module": {
        "module": "misp.MISP",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "scan an observable on a custom MISP instance",
    "disabled": False,
    "soft_time_limit": 30,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "domain", "url", "hash", "generic"],
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
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "debug",
        "type": "bool",
        "description": "Enable debug logs.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "limit",
        "type": "int",
        "description": "Limit the number of results returned",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "from_days",
        "type": "int",
        "description": "Check only events created in the past X days. 0 for no filter",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "ssl_check",
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "strict_search",
        "type": "bool",
        "description": "Search strictly on the observable value (True) or search on attributes containing observable value (False)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "filter_on_type",
        "type": "bool",
        "description": "Filter the search on the type of the observable.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "enforce_warninglist",
        "type": "bool",
        "description": "Remove any attributes from the result that would cause a hit on a warninglist entry.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "self_signed_certificate",
        "type": "bool",
        "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "debug",
            "type": "bool",
            "description": "Enable debug logs.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:18.092259Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "limit",
            "type": "int",
            "description": "Limit the number of results returned",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 50,
        "updated_at": "2024-02-09T10:52:18.107503Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "from_days",
            "type": "int",
            "description": "Check only events created in the past X days. 0 for no filter",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 90,
        "updated_at": "2024-02-09T10:52:18.122488Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "ssl_check",
            "type": "bool",
            "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:18.138551Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "strict_search",
            "type": "bool",
            "description": "Search strictly on the observable value (True) or search on attributes containing observable value (False)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:18.152993Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "filter_on_type",
            "type": "bool",
            "description": "Filter the search on the type of the observable.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:18.167009Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "enforce_warninglist",
            "type": "bool",
            "description": "Remove any attributes from the result that would cause a hit on a warninglist entry.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:18.179483Z",
        "owner": None,
        "analyzer_config": "MISP",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "self_signed_certificate",
            "type": "bool",
            "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:18.206089Z",
        "owner": None,
        "analyzer_config": "MISP",
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
        ("analyzers_manager", "0002_0067_analyzer_config_koodous"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
