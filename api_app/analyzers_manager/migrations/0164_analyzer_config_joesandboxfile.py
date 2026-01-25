from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
    ReverseManyToOneDescriptor,
    ReverseOneToOneDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "joesandbox_file.JoeSandboxFile",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "JoeSandboxFile",
    "description": "[JoeSandboxFile](https://www.joesandbox.com/) is a comprehensive malware analysis tool, which can be used to perform deep malware analysis, on various platforms such as windows, macos, linux, android.",
    "disabled": False,
    "soft_time_limit": 1800,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": [],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [
        "application/xml",
        "text/xml",
        "application/encrypted",
        "text/plain",
        "application/json",
    ],
    "mapping_data_model": {},
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "url",
        "type": "str",
        "description": "URL for your private JoeSandbox Instance. Defaults to public JoeSandBox URL.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "system_to_use",
        "type": "str",
        "description": "System to use for analysis. Possible values for available systems to use are: \r\n\r\nWindows: w11x64_office, w10x64, w10x64native, w7x64\r\nLinux: lnxubuntu20, lnxubuntu1\r\nMacOS: macvm-mojave\r\n\r\nRead the Intelowl Usage docs, for more info on the systems.",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key",
        "type": "str",
        "description": "API key for JoeSandbox Instance.",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "polling_duration",
        "type": "int",
        "description": "Set the desired polling duration to check when analysis is finished. Defaults to 60 seconds.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "force_new_analysis",
        "type": "bool",
        "description": "Set to True if you want to force a new analysis without checking any pre-existing analysis. Set to False by default",
        "is_secret": False,
        "required": False,
    },
]

values = []


def _get_real_obj(Model, field, value):
    def _get_obj(Model, other_model, value):
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            if isinstance(value, int):
                if Model.__name__ == "PluginConfig":
                    value = other_model.objects.get(name=plugin["name"])
                else:
                    value = other_model.objects.get(pk=value)
            else:
                value = other_model.objects.get(name=value)
        return value

    if (
        type(getattr(Model, field))
        in [
            ForwardManyToOneDescriptor,
            ReverseManyToOneDescriptor,
            ReverseOneToOneDescriptor,
            ForwardOneToOneDescriptor,
        ]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        value = _get_obj(Model, other_model, value)
    elif type(getattr(Model, field)) in [ManyToManyDescriptor] and value:
        other_model = getattr(Model, field).rel.model
        value = [_get_obj(Model, other_model, val) for val in value]
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        value = _get_real_obj(Model, field, value)
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            if value is not None:
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
    atomic = False
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("analyzers_manager", "0163_analyzer_config_guarddoggeneric"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
