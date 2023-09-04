object_ = {
    "name": "Anomali_Threatstream",
    "config": {"queue": "default", "soft_time_limit": 30},
    "python_module": "threatstream.Threatstream",
    "description": "Analyzer to interact with Anomali ThreatStream APIs",
    "disabled": False,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "url", "domain", "hash", "generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "id": 415,
        "name": "limit",
        "type": "str",
        "description": "Number of maximal entries returned",
        "is_secret": False,
        "required": False,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 418,
        "name": "threatstream_analysis",
        "type": "str",
        "description": "API endpoint called: options are `confidence`, `intelligence` and `passive_dns`",
        "is_secret": False,
        "required": False,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 419,
        "name": "minimal_confidence",
        "type": "str",
        "description": "Minimal Confidence filter",
        "is_secret": False,
        "required": False,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 420,
        "name": "modified_after",
        "type": "str",
        "description": "Filter on entries modified after a specific date. Date must be specified in this format: YYYYMMDDThhmmss where T denotes the start of the value for time, in UTC time. For example, 2014-10-02T20:44:35.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 421,
        "name": "must_active",
        "type": "bool",
        "description": "Only return active entries",
        "is_secret": False,
        "required": False,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 416,
        "name": "api_user_name",
        "type": "str",
        "description": "API USER for Anomali Threatstream",
        "is_secret": True,
        "required": True,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 417,
        "name": "api_key_name",
        "type": "str",
        "description": "API Key for Anomali Threatstream",
        "is_secret": True,
        "required": True,
        "analyzer_config": "Anomali_Threatstream",
        "connector_config": None,
        "visualizer_config": None,
    },
]

values = [
    {
        "id": 301,
        "value": "100",
        "for_organization": False,
        "updated_at": "2023-05-12T17:00:16.423351Z",
        "owner": None,
        "parameter": 415,
    },
    {
        "id": 302,
        "value": "intelligence",
        "for_organization": False,
        "updated_at": "2023-05-12T17:00:16.429320Z",
        "owner": None,
        "parameter": 418,
    },
    {
        "id": 303,
        "value": "0",
        "for_organization": False,
        "updated_at": "2023-05-12T17:00:16.431856Z",
        "owner": None,
        "parameter": 419,
    },
    {
        "id": 304,
        "value": "1900-10-02T20:44:35",
        "for_organization": False,
        "updated_at": "2023-05-12T17:00:16.434305Z",
        "owner": None,
        "parameter": 420,
    },
    {
        "id": 305,
        "value": False,
        "for_organization": False,
        "updated_at": "2023-05-12T17:00:16.436733Z",
        "owner": None,
        "parameter": 421,
    },
]


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = object_.pop("model")
    Model = apps.get_model(*python_path.split("."))
    o = Model(**object_)
    o.full_clean()
    o.save()
    param_maps = {}
    for param in params:
        param_id = param.pop("id")
        for key in ["analyzer_config", "connector_config", "visualizer_config"]:
            if param[key]:
                param[key] = o
                break
        par = Parameter(**param)
        par.full_clean()
        par.save()
        param_maps[param_id] = par
    for value in values:
        value.pop("id")
        parameter = param_maps[value["parameter"]]
        value["parameter"] = parameter
        value = PluginConfig(**value)
        value.full_clean()
        value.save()


def reverse_migrate(apps, schema_editor):
    python_path = object_.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=object_["name"]).delete()


from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0030_pluginconfig_repositories"),
        ("analyzers_manager", "0025_alert_tlp_and_analyzer_cleanup"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
