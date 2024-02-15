from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "YARAify_File_Scan",
    "python_module": {
        "module": "yaraify_file_scan.YARAifyFileScan",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "description": "Scan a file against public and non-public YARA and ClamAV signatures in [YARAify service](https://yaraify.abuse.ch/). With TLP `CLEAR`, in case the hash is not found, you would send the file to the service.",
    "disabled": False,
    "soft_time_limit": 500,
    "routing_key": "long",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "AMBER",
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
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "unpack",
        "type": "bool",
        "description": "Defines whether to unpack the file.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "send_file",
        "type": "bool",
        "description": "Defines whether the file should be sent for analysis or not (in the latter case hash only check would be done)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "result_max",
        "type": "int",
        "description": "Max number of results you want to display (default: 25, max: 1'000)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "share_file",
        "type": "bool",
        "description": "Defines whether the file is public and may be shared with 3rd parties.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "skip_known",
        "type": "bool",
        "description": "YARAify will not process the file if the file is already known.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "skip_noisy",
        "type": "bool",
        "description": "YARAify skips the file if it already has been scanned at least 10 times within the past 24 hours. It will return the latest task_id instead",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "clamav_scan",
        "type": "bool",
        "description": "Defines whether to scan the file with ClamAV.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key_identifier",
        "type": "str",
        "description": "Optional identifier to associate this submission with",
        "is_secret": True,
        "required": False,
    },
    {
        "python_module": {
            "module": "yaraify_file_scan.YARAifyFileScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "Optional key to receive results from public (TLP:CLEAR) and non-public (TLP:GREEN, TLP:AMBER and TLP:RED) YARA rules.",
        "is_secret": True,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "unpack",
            "type": "bool",
            "description": "Defines whether to unpack the file.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:20.624667Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "send_file",
            "type": "bool",
            "description": "Defines whether the file should be sent for analysis or not (in the latter case hash only check would be done)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:20.637754Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "result_max",
            "type": "int",
            "description": "Max number of results you want to display (default: 25, max: 1'000)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 25,
        "updated_at": "2024-02-09T10:52:20.651957Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "share_file",
            "type": "bool",
            "description": "Defines whether the file is public and may be shared with 3rd parties.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:20.663677Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "skip_known",
            "type": "bool",
            "description": "YARAify will not process the file if the file is already known.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:20.677107Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "skip_noisy",
            "type": "bool",
            "description": "YARAify skips the file if it already has been scanned at least 10 times within the past 24 hours. It will return the latest task_id instead",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:20.691102Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yaraify_file_scan.YARAifyFileScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "clamav_scan",
            "type": "bool",
            "description": "Defines whether to scan the file with ClamAV.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:20.701978Z",
        "owner": None,
        "analyzer_config": "YARAify_File_Scan",
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
        ("analyzers_manager", "0002_0139_analyzer_config_xlm_macro_deobfuscator"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
