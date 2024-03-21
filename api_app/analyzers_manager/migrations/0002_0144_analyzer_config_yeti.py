from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "YETI",
    "python_module": {
        "module": "yeti.YETI",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "scan an observable on a custom YETI instance",
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
            "module": "yeti.YETI",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "regex",
        "type": "bool",
        "description": "Use this if you are searching for observables using a regex.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yeti.YETI",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "verify_ssl",
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your YETI instance has not SSL enabled.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yeti.YETI",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "results_count",
        "type": "int",
        "description": "Use this to limit the maximum number of results obtained from a search.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yeti.YETI",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "API key for your YETI instance",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "yeti.YETI",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_key_name",
        "type": "str",
        "description": "API URL of your YETI instance",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "yeti.YETI",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "regex",
            "type": "bool",
            "description": "Use this if you are searching for observables using a regex.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:20.844799Z",
        "owner": None,
        "analyzer_config": "YETI",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yeti.YETI",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "verify_ssl",
            "type": "bool",
            "description": "Enable SSL certificate server verification. Change this if your YETI instance has not SSL enabled.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:20.861061Z",
        "owner": None,
        "analyzer_config": "YETI",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yeti.YETI",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "results_count",
            "type": "int",
            "description": "Use this to limit the maximum number of results obtained from a search.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 50,
        "updated_at": "2024-02-09T10:52:20.876848Z",
        "owner": None,
        "analyzer_config": "YETI",
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
        ("analyzers_manager", "0002_0143_analyzer_config_yaraify_search"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
