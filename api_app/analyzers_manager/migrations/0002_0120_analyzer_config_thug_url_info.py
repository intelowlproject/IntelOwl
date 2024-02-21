from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Thug_URL_Info",
    "python_module": {
        "module": "thug_url.ThugUrl",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Perform hybrid dynamic/static analysis on a URL",
    "disabled": False,
    "soft_time_limit": 600,
    "routing_key": "local",
    "health_check_status": True,
    "type": "observable",
    "docker_based": True,
    "maximum_tlp": "RED",
    "observable_supported": ["domain", "url"],
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
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "proxy",
        "type": "str",
        "description": "option `-p`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "use_proxy",
        "type": "bool",
        "description": "option `-p`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "dom_events",
        "type": "str",
        "description": "See [Thug docs: dom events handling](https://buffer.github.io/thug/doc/usage.html#dom-events-handling).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "user_agent",
        "type": "str",
        "description": "See [Thug docs: browser personality](https://buffer.github.io/thug/doc/usage.html#browser-personality).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "enable_awis",
        "type": "bool",
        "description": "option `-E`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "thug_url.ThugUrl",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "enable_image_processing_analysis",
        "type": "bool",
        "description": "option `-a`",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "proxy",
            "type": "str",
            "description": "option `-p`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:19.748697Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "use_proxy",
            "type": "bool",
            "description": "option `-p`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:19.762348Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "dom_events",
            "type": "str",
            "description": "See [Thug docs: dom events handling](https://buffer.github.io/thug/doc/usage.html#dom-events-handling).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "click,mouseover",
        "updated_at": "2024-02-09T10:52:19.777091Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "user_agent",
            "type": "str",
            "description": "See [Thug docs: browser personality](https://buffer.github.io/thug/doc/usage.html#browser-personality).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "winxpie60",
        "updated_at": "2024-02-09T10:52:19.793319Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "enable_awis",
            "type": "bool",
            "description": "option `-E`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:19.809742Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "thug_url.ThugUrl",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "enable_image_processing_analysis",
            "type": "bool",
            "description": "option `-a`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:19.825585Z",
        "owner": None,
        "analyzer_config": "Thug_URL_Info",
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
        ("analyzers_manager", "0002_0119_analyzer_config_thug_html_info"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
