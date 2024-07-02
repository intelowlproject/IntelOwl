from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "goresym.GoReSym",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "GoReSym",
    "description": "[GoReSym](https://github.com/mandiant/GoReSym) is a Go symbol parser that extracts program metadata (such as CPU architecture, OS, endianness, compiler version, etc), function metadata (start & end addresses, names, sources), filename and line number metadata, and embedded structures and types.",
    "disabled": False,
    "soft_time_limit": 25,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": [],
    "supported_filetypes": ["application/x-executable"],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "goresym.GoReSym",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "flags",
        "type": "str",
        "description": 'Here are all the available flags:\r\n\r\n* `-d` ("default", optional) flag will print standard Go packages in addition to user packages.\r\n* `-p` ("paths", optional) flag will print any file paths embedded in the `pclntab`.\r\n* `-t` ("types", optional) flag will print Go type names.\r\n* `-m <virtual address>` ("manual", optional) flag will dump the `RTYPE` structure recursively at the given virtual address\r\n* `-v <version string>` ("version", optional) flag will override automated version detection and use the provided version. This is needed for some stripped binaries. Type parsing will fail if the version is not accurate.\r\n* `-human` (optional) flag will print a flat text listing instead of JSON. Especially useful when printing structure and interface types.\r\n* `-about` (optional) flag with print out license information\r\nexample string: "-d -p -t" [white-space separated]',
        "is_secret": False,
        "required": False,
    }
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "goresym.GoReSym",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "flags",
            "type": "str",
            "description": 'Here are all the available flags:\r\n\r\n* `-d` ("default", optional) flag will print standard Go packages in addition to user packages.\r\n* `-p` ("paths", optional) flag will print any file paths embedded in the `pclntab`.\r\n* `-t` ("types", optional) flag will print Go type names.\r\n* `-m <virtual address>` ("manual", optional) flag will dump the `RTYPE` structure recursively at the given virtual address\r\n* `-v <version string>` ("version", optional) flag will override automated version detection and use the provided version. This is needed for some stripped binaries. Type parsing will fail if the version is not accurate.\r\n* `-human` (optional) flag will print a flat text listing instead of JSON. Especially useful when printing structure and interface types.\r\n* `-about` (optional) flag with print out license information\r\nexample string: "-d -p -t" [white-space separated]',
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "GoReSym",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": "-t -d -p",
        "updated_at": "2024-06-28T18:48:55.156666Z",
        "owner": None,
    }
]


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
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
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
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0100_add_x_executable"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]