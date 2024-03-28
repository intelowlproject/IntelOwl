from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Dragonfly_Emulation",
    "python_module": {
        "module": "dragonfly.DragonflyEmulation",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "description": "Emulate malware against [Dragonfly](https://dragonfly.certego.net/?utm_source=intelowl) sandbox by [Certego S.R.L](https://certego.net).",
    "disabled": False,
    "soft_time_limit": 400,
    "routing_key": "long",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": [],
    "supported_filetypes": ["application/x-dosexec", "application/octet-stream"],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "root",
        "type": "bool",
        "description": "If `true`, emulate with root permissions",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "private",
        "type": "bool",
        "description": "If `true`, mark the analysis as private so it's accessible to you and members within your organization only",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "profiles",
        "type": "list",
        "description": "List of profile indices for emulators. Refer to [profiles list](https://dragonfly.certego.net/dashboard/profiles?utm_source=intelowl).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "allow_actions",
        "type": "bool",
        "description": "If `true`, run actions when a rule matches",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "operating_system",
        "type": "str",
        "description": "Enum: `WINDOW`|`LINUX`| or leave blank string for automatic detection",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "Dragonfly API key. Generate [here](https://dragonfly.certego.net/me/sessions?utm_source=intelowl).",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "dragonfly.DragonflyEmulation",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "url_key_name",
        "type": "str",
        "description": "Dragonfly instance URL. Don't change this.",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "dragonfly.DragonflyEmulation",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "root",
            "type": "bool",
            "description": "If `true`, emulate with root permissions",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:17.095304Z",
        "owner": None,
        "analyzer_config": "Dragonfly_Emulation",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dragonfly.DragonflyEmulation",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "private",
            "type": "bool",
            "description": "If `true`, mark the analysis as private so it's accessible to you and members within your organization only",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:17.106896Z",
        "owner": None,
        "analyzer_config": "Dragonfly_Emulation",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dragonfly.DragonflyEmulation",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "profiles",
            "type": "list",
            "description": "List of profile indices for emulators. Refer to [profiles list](https://dragonfly.certego.net/dashboard/profiles?utm_source=intelowl).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": [1, 2],
        "updated_at": "2024-02-09T10:52:17.119397Z",
        "owner": None,
        "analyzer_config": "Dragonfly_Emulation",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dragonfly.DragonflyEmulation",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "allow_actions",
            "type": "bool",
            "description": "If `true`, run actions when a rule matches",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:17.131627Z",
        "owner": None,
        "analyzer_config": "Dragonfly_Emulation",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dragonfly.DragonflyEmulation",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "operating_system",
            "type": "str",
            "description": "Enum: `WINDOW`|`LINUX`| or leave blank string for automatic detection",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:17.143946Z",
        "owner": None,
        "analyzer_config": "Dragonfly_Emulation",
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
        ("analyzers_manager", "0002_0035_analyzer_config_doc_info"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
