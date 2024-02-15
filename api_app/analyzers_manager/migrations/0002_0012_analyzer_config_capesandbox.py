from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "CapeSandbox",
    "python_module": {
        "module": "cape_sandbox.CAPEsandbox",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "description": "Automatic scan of suspicious files using [CapeSandbox](https://github.com/kevoreilly/CAPEv2) API",
    "disabled": False,
    "soft_time_limit": 1000,
    "routing_key": "long",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": [],
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
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "max_tries",
        "type": "int",
        "description": "Number of max tries while trying to poll the CAPESandbox API.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "poll_distance",
        "type": "int",
        "description": "Seconds to wait before moving on to the next poll attempt.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "url_key_name",
        "type": "str",
        "description": "URL for the CapeSandbox instance. If none provided, It uses the API provided by CAPESandbox by default.",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "options",
        "type": "str",
        "description": 'Specify options for the analysis package (e.g. "name=value,name2=value2").',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "package",
        "type": "str",
        "description": "Specify an analysis package.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "timeout",
        "type": "int",
        "description": "Specify an analysis timeout.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "priority",
        "type": "int",
        "description": "Specify a priority for the analysis (1=low, 2=medium, 3=high).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "machine",
        "type": "str",
        "description": "Specify the identifier of a machine you want to use (empty = first available).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "platform",
        "type": "str",
        "description": "Specify the operating system platform you want to use (windows/darwin/linux).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "memory",
        "type": "bool",
        "description": "Enable to take a memory dump of the analysis machine.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "enforce_timeout",
        "type": "bool",
        "description": "Enable to force the analysis to run for the full timeout period.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "custom",
        "type": "str",
        "description": "Specify any custom value.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "tags",
        "type": "str",
        "description": "Specify tags identifier of a machine you want to use.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "route",
        "type": "str",
        "description": "Specify an analysis route.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "certificate",
        "type": "str",
        "description": "CapSandbox SSL certificate (multiline string).",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "cape_sandbox.CAPEsandbox",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "requests_timeout",
        "type": "int",
        "description": "Python requests HTTP GET/POST timeout",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "max_tries",
            "type": "int",
            "description": "Number of max tries while trying to poll the CAPESandbox API.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 50,
        "updated_at": "2024-02-09T10:52:22.114079Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "poll_distance",
            "type": "int",
            "description": "Seconds to wait before moving on to the next poll attempt.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 30,
        "updated_at": "2024-02-09T10:52:22.141845Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "options",
            "type": "str",
            "description": 'Specify options for the analysis package (e.g. "name=value,name2=value2").',
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.260381Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "package",
            "type": "str",
            "description": "Specify an analysis package.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.321897Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "timeout",
            "type": "int",
            "description": "Specify an analysis timeout.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 180,
        "updated_at": "2024-02-09T10:52:22.367839Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "priority",
            "type": "int",
            "description": "Specify a priority for the analysis (1=low, 2=medium, 3=high).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 1,
        "updated_at": "2024-02-09T10:52:22.397102Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "machine",
            "type": "str",
            "description": "Specify the identifier of a machine you want to use (empty = first available).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.423279Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "platform",
            "type": "str",
            "description": "Specify the operating system platform you want to use (windows/darwin/linux).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.469120Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "memory",
            "type": "bool",
            "description": "Enable to take a memory dump of the analysis machine.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:22.495485Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "enforce_timeout",
            "type": "bool",
            "description": "Enable to force the analysis to run for the full timeout period.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:22.519750Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "custom",
            "type": "str",
            "description": "Specify any custom value.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.549002Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "tags",
            "type": "str",
            "description": "Specify tags identifier of a machine you want to use.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.575749Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "route",
            "type": "str",
            "description": "Specify an analysis route.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:22.599727Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "cape_sandbox.CAPEsandbox",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "requests_timeout",
            "type": "int",
            "description": "Python requests HTTP GET/POST timeout",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 10,
        "updated_at": "2024-02-09T10:52:28.988123Z",
        "owner": None,
        "analyzer_config": "CapeSandbox",
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
        ("analyzers_manager", "0002_0011_analyzer_config_capa_info_shellcode"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
