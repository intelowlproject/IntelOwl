from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": {
            "minute": "0",
            "hour": "0",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "module": "feodo_tracker.Feodo_Tracker",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "Feodo_Tracker",
    "description": "[Feodo Tracker](https://feodotracker.abuse.ch/) offers various blocklists,\r\n    helping network owners to protect their\r\n    users from Dridex and Emotet/Heodo.",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": ["ip"],
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
            "module": "feodo_tracker.Feodo_Tracker",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "use_recommended_url",
        "type": "bool",
        "description": "use recommended [db](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json)",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "feodo_tracker.Feodo_Tracker",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "update_on_run",
        "type": "bool",
        "description": "update analyzer db on every run (Analyzer db\r\n is updated once in every 24 hours by default).",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "feodo_tracker.Feodo_Tracker",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "use_recommended_url",
            "type": "bool",
            "description": "use recommended [db](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json)",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Feodo_Tracker",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-15T03:48:59.096424Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "feodo_tracker.Feodo_Tracker",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "update_on_run",
            "type": "bool",
            "description": "update analyzer db on every run (Analyzer db\r\n is updated once in every 24 hours by default).",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Feodo_Tracker",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-15T03:48:59.113563Z",
        "owner": None,
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
            if isinstance(value, int):
                value = other_model.objects.get(pk=value)
            else:
                value = other_model.objects.get(name=value)
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
    atomic = False
    dependencies = [
        ("api_app", "0061_job_depth_analysis"),
        ("analyzers_manager", "0067_update_misp"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
