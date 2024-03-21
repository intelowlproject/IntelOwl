from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "VirusTotal_v3_Get_Observable",
    "python_module": {
        "module": "vt.vt3_get.VirusTotalv3",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "search an observable in the VirusTotal DB",
    "disabled": False,
    "soft_time_limit": 800,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "domain", "url", "hash"],
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
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "max_tries",
        "type": "int",
        "description": "How many times we poll the VT API for scan results",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "poll_distance",
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "rescan_max_tries",
        "type": "int",
        "description": "How many times we poll the VT API for RE-scan results (samples already available to VT)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "rescan_poll_distance",
        "type": "int",
        "description": "IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "include_sigma_analyses",
        "type": "bool",
        "description": "Include sigma analysis report alongside default scan report. This will cost additional quota.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "relationships_elements",
        "type": "int",
        "description": "Number of elements to retrieve for each relationships",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "force_active_scan_if_old",
        "type": "bool",
        "description": "If the sample is old, it would be rescanned. This will cost additional quota.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "relationships_to_request",
        "type": "list",
        "description": "Include a list of relationships to request if available. This will cost additional quota.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "include_behaviour_summary",
        "type": "bool",
        "description": "Include a summary of behavioral analysis reports alongside default scan report. This will cost additional quota.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "days_to_say_that_a_scan_is_old",
        "type": "int",
        "description": "How many days are required to consider a scan old to force rescan",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vt.vt3_get.VirusTotalv3",
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
            "module": "vt.vt3_get.VirusTotalv3",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url_sub_path",
        "type": "str",
        "description": "if you want to query a specific subpath of the base endpoint, i.e: `analyses`",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "max_tries",
            "type": "int",
            "description": "How many times we poll the VT API for scan results",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 10,
        "updated_at": "2024-02-09T10:52:21.375283Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "poll_distance",
            "type": "int",
            "description": "IntelOwl would sleep for this time between each poll to VT APIs",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 30,
        "updated_at": "2024-02-09T10:52:21.399856Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "rescan_max_tries",
            "type": "int",
            "description": "How many times we poll the VT API for RE-scan results (samples already available to VT)",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 5,
        "updated_at": "2024-02-09T10:52:21.411674Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "rescan_poll_distance",
            "type": "int",
            "description": "IntelOwl would sleep for this time between each poll to VT APIs after having started a RE-scan",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 120,
        "updated_at": "2024-02-09T10:52:21.424006Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "include_sigma_analyses",
            "type": "bool",
            "description": "Include sigma analysis report alongside default scan report. This will cost additional quota.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:21.436444Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "relationships_elements",
            "type": "int",
            "description": "Number of elements to retrieve for each relationships",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 1,
        "updated_at": "2024-02-09T10:52:21.454125Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "force_active_scan_if_old",
            "type": "bool",
            "description": "If the sample is old, it would be rescanned. This will cost additional quota.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:21.492808Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "relationships_to_request",
            "type": "list",
            "description": "Include a list of relationships to request if available. This will cost additional quota.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": [],
        "updated_at": "2024-02-09T10:52:21.527682Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "include_behaviour_summary",
            "type": "bool",
            "description": "Include a summary of behavioral analysis reports alongside default scan report. This will cost additional quota.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:21.569911Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "days_to_say_that_a_scan_is_old",
            "type": "int",
            "description": "How many days are required to consider a scan old to force rescan",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": 30,
        "updated_at": "2024-02-09T10:52:21.612115Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vt.vt3_get.VirusTotalv3",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "url_sub_path",
            "type": "str",
            "description": "if you want to query a specific subpath of the base endpoint, i.e: `analyses`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:21.387972Z",
        "owner": None,
        "analyzer_config": "VirusTotal_v3_Get_Observable",
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
        ("analyzers_manager", "0002_0130_analyzer_config_virustotal_v3_get_file"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
