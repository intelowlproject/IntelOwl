from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Popular_URL_Reputation_Services",
    "analyzers": [
        "CloudFlare_Malicious_Detector",
        "DNS0_EU_Malicious_Detector",
        "GoogleSafebrowsing",
        "InQuest_REPdb",
        "OTXQuery",
        "PhishingArmy",
        "Phishtank",
        "Quad9_Malicious_Detector",
        "ThreatFox",
        "URLhaus",
        "VirusTotal_v3_Get_Observable",
    ],
    "connectors": [],
    "pivots": [],
    "for_organization": False,
    "description": "Collection of the most popular and free reputation analyzers for URLs and Domains",
    "disabled": False,
    "type": ["url", "domain"],
    "runtime_configuration": {"analyzers": {}, "connectors": {}, "visualizers": {}},
    "scan_mode": 2,
    "scan_check_time": "1 00:00:00",
    "tlp": "AMBER",
    "owner": None,
    "disabled_in_organizations": [],
    "tags": [],
    "model": "playbooks_manager.PlaybookConfig",
}

params = []

values = []


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
        (
            "playbooks_manager",
            "0002_0002_playbook_config_popular_ip_reputation_services",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
