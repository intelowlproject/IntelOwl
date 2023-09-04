from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "ThreatFox",
    "config": {"queue": "default", "soft_time_limit": 60},
    "schedule": {
        "minute": "30",
        "hour": "7",
        "day_of_week": "*",
        "day_of_month": "*",
        "month_of_year": "*",
    },
    "periodic_task": {
        "crontab": {
            "minute": "30",
            "hour": "7",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "name": "ThreatFoxIngestor",
        "task": "intel_owl.tasks.execute_ingestor",
        "kwargs": '{"config_pk": "ThreatFox"}',
        "queue": "default",
        "enabled": False,
    },
    "description": "Threatfox ingestor",
    "disabled": True,
    "python_module": "threatfox.ThreatFox",
    "playbook_to_execute": "Popular_IP_Reputation_Services",
    "user": {"username": "ThreatFoxIngestor"},
    "model": "ingestors_manager.IngestorConfig",
}

params = [
    {
        "id": 430,
        "name": "days",
        "type": "int",
        "description": "Days to check. From 1 to 7",
        "is_secret": False,
        "required": True,
        "analyzer_config": None,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": "ThreatFox",
    }
]

values = [
    {
        "id": 331,
        "value": 1,
        "for_organization": False,
        "updated_at": "2023-07-31T13:54:51.040330Z",
        "owner": None,
        "parameter": 430,
    }
]


def _get_real_obj(Model, field, value):
    if type(getattr(Model, field)) in [
        ForwardManyToOneDescriptor,
        ForwardOneToOneDescriptor,
    ]:
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


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    mtm, no_mtm = {}, {}
    for field, value in plugin.items():
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            value = _get_real_obj(Model, field, value)
            no_mtm[field] = value
    o = Model(**no_mtm)
    o.full_clean()
    o.save()
    for field, value in mtm.items():
        attribute = getattr(o, field)
        attribute.set(value)
    param_maps = {}
    for param in params:
        param_id = param.pop("id")
        for key in [
            "analyzer_config",
            "connector_config",
            "visualizer_config",
            "ingestor_config",
        ]:
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
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api_app", "0036_alter_parameter_unique_together_and_more"),
        (
            "ingestors_manager",
            "0002_remove_ingestorconfig_disabled_in_organizations_and_more",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
