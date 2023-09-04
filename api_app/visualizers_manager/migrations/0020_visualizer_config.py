from django.db import migrations

object_ = {
    "name": "IP_Reputation",
    "config": {"queue": "default", "soft_time_limit": 60},
    "python_module": "ip_reputation_services.IPReputationServices",
    "description": 'Visualizer for the Playbook "Popular_IP_Reputation_Services"',
    "disabled": False,
    "disabled_in_organizations": [],
    "analyzers": [
        "TalosReputation",
        "Crowdsec",
        "OTXQuery",
        "TorProject",
        "AbuseIPDB",
        "GreedyBear",
        "VirusTotal_v3_Get_Observable",
        "FireHol_IPList",
        "URLhaus",
        "ThreatFox",
        "InQuest_REPdb",
        "GreyNoiseCommunity",
    ],
    "connectors": [],
    "model": "visualizers_manager.VisualizerConfig",
}

params = []

values = []


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = object_.pop("model")
    Model = apps.get_model(*python_path.split("."))
    analyzers = object_.pop("analyzers")
    connectors = object_.pop("connectors")
    disabled_in_organizations = object_.pop("disabled_in_organizations")
    o = Model(**object_)
    o.full_clean()
    o.save()
    o.analyzers.set(analyzers)
    o.connectors.set(connectors)
    o.disabled_in_organizations.set(disabled_in_organizations)
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


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0030_pluginconfig_repositories"),
        ("visualizers_manager", "0019_dns_visualizer_change"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
