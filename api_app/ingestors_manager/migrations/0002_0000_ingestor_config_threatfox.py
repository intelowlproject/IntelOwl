from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "ThreatFox",
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": {
            "minute": "30",
            "hour": "7",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "update_task": {
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
        "module": "threatfox.ThreatFox",
        "base_path": "api_app.ingestors_manager.ingestors",
    },
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
    "user": {
        "username": "ThreatFoxIngestor",
        "first_name": "",
        "last_name": "",
        "email": "",
    },
    "description": "Threatfox ingestor",
    "disabled": True,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "maximum_jobs": 10,
    "health_check_task": None,
    "playbook_to_execute": "Popular_IP_Reputation_Services",
    "model": "ingestors_manager.IngestorConfig",
}

params = [
    {
        "python_module": {
            "module": "threatfox.ThreatFox",
            "base_path": "api_app.ingestors_manager.ingestors",
        },
        "name": "days",
        "type": "int",
        "description": "Days to check. From 1 to 7",
        "is_secret": False,
        "required": True,
    }
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "threatfox.ThreatFox",
                "base_path": "api_app.ingestors_manager.ingestors",
            },
            "name": "days",
            "type": "int",
            "description": "Days to check. From 1 to 7",
            "is_secret": False,
            "required": True,
        },
        "for_organization": False,
        "value": 1,
        "updated_at": "2024-02-09T10:52:22.088107Z",
        "owner": None,
        "analyzer_config": None,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": "ThreatFox",
        "pivot_config": None,
    }
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
        ("ingestors_manager", "0001_initial_squashed"),
        ("playbooks_manager", "0002_0004_playbook_config_sample_static_analysis"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
