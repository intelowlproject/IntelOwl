from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "SSAPINet",
    "python_module": {
        "module": "ss_api_net.SSAPINet",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Get a screenshot of a web page using screenshotapi.net. For configuration, Refer to the [docs](https://screenshotapi.net/documentation).",
    "disabled": False,
    "soft_time_limit": 300,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["url"],
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
            "module": "ss_api_net.SSAPINet",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "extra_api_params",
        "type": "dict",
        "description": "Refer to their docs](https://screenshotapi.net/documentation).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ss_api_net.SSAPINet",
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
            "module": "ss_api_net.SSAPINet",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "proxy",
        "type": "str",
        "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ss_api_net.SSAPINet",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "output",
        "type": "str",
        "description": "Specify output type (options: `image` i.e. raw base64 encoded image, `json` i.e. containing link)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "ss_api_net.SSAPINet",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "use_proxy",
        "type": "bool",
        "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server.",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "ss_api_net.SSAPINet",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "extra_api_params",
            "type": "dict",
            "description": "Refer to their docs](https://screenshotapi.net/documentation).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": {
            "fresh": False,
            "full_page": True,
            "lazy_load": False,
            "destroy_screenshot": False,
        },
        "updated_at": "2024-02-09T10:52:19.568118Z",
        "owner": None,
        "analyzer_config": "SSAPINet",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "ss_api_net.SSAPINet",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "proxy",
            "type": "str",
            "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:19.516291Z",
        "owner": None,
        "analyzer_config": "SSAPINet",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "ss_api_net.SSAPINet",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "output",
            "type": "str",
            "description": "Specify output type (options: `image` i.e. raw base64 encoded image, `json` i.e. containing link)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "image",
        "updated_at": "2024-02-09T10:52:19.538962Z",
        "owner": None,
        "analyzer_config": "SSAPINet",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "ss_api_net.SSAPINet",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "use_proxy",
            "type": "bool",
            "description": "Use the `use_proxy` and `proxy` options to pass your request through a proxy server.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:19.554907Z",
        "owner": None,
        "analyzer_config": "SSAPINet",
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
        ("analyzers_manager", "0002_0102_analyzer_config_rtf_info"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
