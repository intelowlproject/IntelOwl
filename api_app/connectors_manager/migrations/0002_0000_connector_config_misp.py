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
        "base_path": "api_app.connectors_manager.connectors",
    },
    "description": "Automatically creates an event on your MISP instance, linking the successful analysis on IntelOwl",
    "disabled": False,
    "soft_time_limit": 30,
    "routing_key": "default",
    "health_check_status": True,
    "maximum_tlp": "CLEAR",
    "run_on_failure": False,
    "health_check_task": None,
    "model": "connectors_manager.ConnectorConfig",
}

params = [
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "tlp",
        "type": "str",
        "description": "Change this as per your organization's threat sharing conventions.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.connectors_manager.connectors",
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
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "ssl_check",
        "type": "bool",
        "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "self_signed_certificate",
        "type": "bool",
        "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `<project_location>/configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "API key for your MISP instance",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "misp.MISP",
            "base_path": "api_app.connectors_manager.connectors",
        },
        "name": "url_key_name",
        "type": "str",
        "description": "URL of your MISP instance",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.connectors_manager.connectors",
            },
            "name": "tlp",
            "type": "str",
            "description": "Change this as per your organization's threat sharing conventions.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "clear",
        "updated_at": "2024-02-09T10:52:16.102464Z",
        "owner": None,
        "analyzer_config": None,
        "connector_config": "MISP",
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.connectors_manager.connectors",
            },
            "name": "debug",
            "type": "bool",
            "description": "Enable debug logs.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:16.116031Z",
        "owner": None,
        "analyzer_config": None,
        "connector_config": "MISP",
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.connectors_manager.connectors",
            },
            "name": "ssl_check",
            "type": "bool",
            "description": "Enable SSL certificate server verification. Change this if your MISP instance has not SSL enabled.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:16.129283Z",
        "owner": None,
        "analyzer_config": None,
        "connector_config": "MISP",
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "misp.MISP",
                "base_path": "api_app.connectors_manager.connectors",
            },
            "name": "self_signed_certificate",
            "type": "bool",
            "description": "If ssl_check and this flag are True, the analyzer will leverage a CA_BUNDLE to authenticate against the MISP instance. IntelOwl will look for it at this path: `<project_location>/configuration/misp_ssl.crt`. Remember that this file should be readable by the application (`www-data` user must read this)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:16.144268Z",
        "owner": None,
        "analyzer_config": None,
        "connector_config": "MISP",
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
        ("connectors_manager", "0001_initial_squashed"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
