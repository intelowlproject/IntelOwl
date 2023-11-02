object_ = {
    "name": "PhishingArmy",
    "config": {"queue": "default", "soft_time_limit": 60},
    "python_module": "phishing_army.PhishingArmy",
    "description": "Search an observable in the [PhishingArmy](https://phishing.army/) blocklist",
    "disabled": False,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": ["url", "domain"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = []

values = []


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
        ("analyzers_manager", "0026_anomali_threatstream"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
