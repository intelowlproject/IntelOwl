from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
    ReverseManyToOneDescriptor,
    ReverseOneToOneDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "virus_total.VirusTotal",
        "base_path": "api_app.ingestors_manager.ingestors",
    },
    "schedule": {
        "minute": "0",
        "hour": "*",
        "day_of_week": "*",
        "day_of_month": "*",
        "month_of_year": "*",
    },
    "periodic_task": {
        "crontab": {
            "minute": "0",
            "hour": "*",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "name": "VirusTotal_Example_QueryIngestor",
        "task": "intel_owl.tasks.execute_ingestor",
        "kwargs": '{"config_name": "VirusTotal_Example_Query"}',
        "queue": "default",
        "enabled": False,
    },
    "user": {
        "username": "VirusTotal_Example_QueryIngestor",
        "profile": {
            "user": {
                "username": "VirusTotal_Example_QueryIngestor",
                "email": "",
                "first_name": "",
                "last_name": "",
                "password": "",
                "is_active": True,
            },
            "company_name": "",
            "company_role": "",
            "twitter_handle": "",
            "discover_from": "other",
            "task_priority": 7,
            "is_robot": True,
        },
    },
    "playbooks_choice": ["FREE_TO_USE_ANALYZERS"],
    "name": "VirusTotal_Example_Query",
    "description": "VirusTotal Ingestor example query taken from: https://blog.virustotal.com/2023/12/protecting-perimeter-with-vt.html. "
    "It requires a valid Premium API key to work properly",
    "disabled": True,
    "soft_time_limit": 60,
    "routing_key": "ingestor",
    "health_check_status": True,
    "maximum_jobs": 30,
    "delay": "00:00:30",
    "model": "ingestors_manager.IngestorConfig",
}

params = [
    {
        "python_module": {
            "module": "virus_total.VirusTotal",
            "base_path": "api_app.ingestors_manager.ingestors",
        },
        "name": "hours",
        "type": "int",
        "description": "Download samples that are up to X hours old",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "virus_total.VirusTotal",
            "base_path": "api_app.ingestors_manager.ingestors",
        },
        "name": "query",
        "type": "str",
        "description": "The query to execute",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "virus_total.VirusTotal",
            "base_path": "api_app.ingestors_manager.ingestors",
        },
        "name": "extract_IOCs",
        "type": "bool",
        "description": "If enabled, this ingestor would extract IOCs instead of downloading retrieved files",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "virus_total.VirusTotal",
            "base_path": "api_app.ingestors_manager.ingestors",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "VT API key",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "virus_total.VirusTotal",
                "base_path": "api_app.ingestors_manager.ingestors",
            },
            "name": "hours",
            "type": "int",
            "description": "Download samples that are up to X hours old",
            "is_secret": False,
            "required": True,
        },
        "analyzer_config": None,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": "VirusTotal_Example_Query",
        "pivot_config": None,
        "for_organization": False,
        "value": 1,
        "updated_at": "2024-09-17T14:38:13.760609Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "virus_total.VirusTotal",
                "base_path": "api_app.ingestors_manager.ingestors",
            },
            "name": "query",
            "type": "str",
            "description": "The query to execute",
            "is_secret": False,
            "required": True,
        },
        "analyzer_config": None,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": "VirusTotal_Example_Query",
        "pivot_config": None,
        "for_organization": False,
        "value": "(type:doc or type:docx or type:xls or type:xlsx) p:5+ (behaviour:powershell or (tag:macros and tag:run-file)) ",
        "updated_at": "2024-09-17T14:21:38.931991Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "virus_total.VirusTotal",
                "base_path": "api_app.ingestors_manager.ingestors",
            },
            "name": "extract_IOCs",
            "type": "bool",
            "description": "If enabled, this ingestor would extract IOCs instead of downloading retrieved files",
            "is_secret": False,
            "required": True,
        },
        "analyzer_config": None,
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": "VirusTotal_Example_Query",
        "pivot_config": None,
        "for_organization": False,
        "value": False,
        "updated_at": "2024-09-17T13:48:18.196119Z",
        "owner": None,
    },
]


def _get_real_obj(Model, field, value):
    def _get_obj(Model, other_model, value):
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            if isinstance(value, int):
                if Model.__name__ == "PluginConfig":
                    value = other_model.objects.get(name=plugin["name"])
                else:
                    value = other_model.objects.get(pk=value)
            else:
                value = other_model.objects.get(name=value)
        return value

    if (
        type(getattr(Model, field))
        in [
            ForwardManyToOneDescriptor,
            ReverseManyToOneDescriptor,
            ReverseOneToOneDescriptor,
            ForwardOneToOneDescriptor,
        ]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        value = _get_obj(Model, other_model, value)
    elif type(getattr(Model, field)) in [ManyToManyDescriptor] and value:
        other_model = getattr(Model, field).rel.model
        value = [_get_obj(Model, other_model, val) for val in value]
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        value = _get_real_obj(Model, field, value)
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            if value is not None:
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
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("ingestors_manager", "0024_remove_ingestorconfig_playbook_to_execute"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
