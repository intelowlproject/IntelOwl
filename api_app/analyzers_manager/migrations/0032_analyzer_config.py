from django.db import migrations

plugin = {
    "name": "CapeSandbox",
    "config": {"queue": "default", "soft_time_limit": 1000},
    "description": "Automatic scan of suspicious files using [CapeSandbox](https://github.com/kevoreilly/CAPEv2) API",
    "disabled": False,
    "python_module": "cape_sandbox.CAPEsandbox",
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": [],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "id": 53,
        "name": "max_tries",
        "type": "int",
        "description": "Number of max tries while trying to poll the CAPESandbox API.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 54,
        "name": "poll_distance",
        "type": "int",
        "description": "Seconds to wait before moving on to the next poll attempt.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 55,
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 56,
        "name": "url_key_name",
        "type": "str",
        "description": "URL for the CapeSandbox instance. If none provided, It uses the API provided by CAPESandbox by default.",
        "is_secret": True,
        "required": True,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 422,
        "name": "options",
        "type": "str",
        "description": 'Specify options for the analysis package (e.g. "name=value,name2=value2").',
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 423,
        "name": "package",
        "type": "str",
        "description": "Specify an analysis package.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 424,
        "name": "timeout",
        "type": "int",
        "description": "Specify an analysis timeout.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 425,
        "name": "priority",
        "type": "int",
        "description": "Specify a priority for the analysis (1=low, 2=medium, 3=high).",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 426,
        "name": "machine",
        "type": "str",
        "description": "Specify the identifier of a machine you want to use (empty = first available).",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 427,
        "name": "platform",
        "type": "str",
        "description": "Specify the operating system platform you want to use (windows/darwin/linux).",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 428,
        "name": "memory",
        "type": "bool",
        "description": "Enable to take a memory dump of the analysis machine.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 429,
        "name": "enforce_timeout",
        "type": "bool",
        "description": "Enable to force the analysis to run for the full timeout period.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 430,
        "name": "custom",
        "type": "str",
        "description": "Specify any custom value.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 431,
        "name": "tags",
        "type": "str",
        "description": "Specify tags identifier of a machine you want to use.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 432,
        "name": "route",
        "type": "str",
        "description": "Specify an analysis route.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 433,
        "name": "certificate",
        "type": "str",
        "description": "CapSandbox SSL certificate (multiline string).",
        "is_secret": True,
        "required": True,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
]

values = [
    {
        "id": 29,
        "value": 50,
        "for_organization": False,
        "updated_at": "2023-07-31T13:33:08.277890Z",
        "owner": None,
        "parameter": 53,
    },
    {
        "id": 30,
        "value": 30,
        "for_organization": False,
        "updated_at": "2023-07-31T13:33:08.280429Z",
        "owner": None,
        "parameter": 54,
    },
    {
        "id": 325,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.330044Z",
        "owner": None,
        "parameter": 55,
    },
    {
        "id": 326,
        "value": "https://www.capesandbox.com",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.334613Z",
        "owner": None,
        "parameter": 56,
    },
    {
        "id": 327,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.337852Z",
        "owner": None,
        "parameter": 422,
    },
    {
        "id": 328,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.341031Z",
        "owner": None,
        "parameter": 423,
    },
    {
        "id": 329,
        "value": 180,
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.344263Z",
        "owner": None,
        "parameter": 424,
    },
    {
        "id": 330,
        "value": 1,
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.347545Z",
        "owner": None,
        "parameter": 425,
    },
    {
        "id": 331,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.351560Z",
        "owner": None,
        "parameter": 426,
    },
    {
        "id": 332,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.354884Z",
        "owner": None,
        "parameter": 427,
    },
    {
        "id": 333,
        "value": False,
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.358166Z",
        "owner": None,
        "parameter": 428,
    },
    {
        "id": 334,
        "value": True,
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.361161Z",
        "owner": None,
        "parameter": 429,
    },
    {
        "id": 335,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.364911Z",
        "owner": None,
        "parameter": 430,
    },
    {
        "id": 336,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.368599Z",
        "owner": None,
        "parameter": 431,
    },
    {
        "id": 337,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.371933Z",
        "owner": None,
        "parameter": 432,
    },
    {
        "id": 338,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T14:57:44.375044Z",
        "owner": None,
        "parameter": 433,
    },
]

params_old = [
    {
        "id": 52,
        "name": "VM_NAME",
        "type": "str",
        "description": "The VM to be used in the analysis.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 53,
        "name": "max_tries",
        "type": "int",
        "description": "Number of max tries while trying to poll the CAPESandbox API.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 54,
        "name": "poll_distance",
        "type": "int",
        "description": "Seconds to wait before moving on to the next poll attempt.",
        "is_secret": False,
        "required": False,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 55,
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
    {
        "id": 56,
        "name": "url_key_name",
        "type": "str",
        "description": "URL for the CapeSandbox instance. If none provided, It uses the API provided by CAPESandbox by default.",
        "is_secret": True,
        "required": True,
        "analyzer_config": "CapeSandbox",
        "connector_config": None,
        "visualizer_config": None,
    },
]

values_old = [
    {
        "id": 28,
        "value": "",
        "for_organization": False,
        "updated_at": "2023-07-31T16:39:05.902099Z",
        "owner": None,
        "parameter": 52,
    },
    {
        "id": 29,
        "value": 50,
        "for_organization": False,
        "updated_at": "2023-07-31T16:39:05.904421Z",
        "owner": None,
        "parameter": 53,
    },
    {
        "id": 30,
        "value": 30,
        "for_organization": False,
        "updated_at": "2023-07-31T16:39:05.906768Z",
        "owner": None,
        "parameter": 54,
    },
    {
        "id": 31,
        "value": "https://www.capesandbox.com",
        "for_organization": False,
        "updated_at": "2023-07-31T16:39:05.909124Z",
        "owner": None,
        "parameter": 56,
    },
]


def _clean_and_restore_snapshot(Parameter, PluginConfig, Model, _params, _values):
    o = Model.objects.get(name=plugin["name"])
    o.full_clean()
    o.save()
    o.parameters.all().delete()

    param_maps = {}
    for param in _params:
        param_id = param.pop("id")
        for key in ["analyzer_config", "connector_config", "visualizer_config"]:
            if param[key]:
                param[key] = o
                break
        par = Parameter(**param)
        par.full_clean()
        par.save()
        param_maps[param_id] = par
    for value in _values:
        value.pop("id")
        parameter = param_maps[value["parameter"]]
        value["parameter"] = parameter
        value = PluginConfig(**value)
        value.full_clean()
        value.save()


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))

    _clean_and_restore_snapshot(Parameter, PluginConfig, Model, params, values)


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))

    _clean_and_restore_snapshot(Parameter, PluginConfig, Model, params_old, values_old)


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0035_pluginconfig_repositories"),
        ("analyzers_manager", "0031_alter_analyzerconfig_name"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
