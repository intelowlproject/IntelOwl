from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": {
            "minute": "0",
            "hour": "0",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "update_schedule": None,
        "module": "vulners.Vulners",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "Vulners",
    "description": "[Vulners](vulners.com) is the most complete and the only fully correlated security intelligence database, which goes through constant updates and links 200+ data sources in a unified machine-readable format. It contains 8 mln+ entries, including CVEs, advisories, exploits, and IoCs — everything you need to stay abreast on the latest security threats.",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "vulners.Vulners",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "score_AI",
        "type": "bool",
        "description": "Score any vulnerability with Vulners AI.\r\nDefault: False",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vulners.Vulners",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "api key for vulners",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "vulners.Vulners",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "skip",
        "type": "int",
        "description": "skip parameter for vulners analyzer",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "vulners.Vulners",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "size",
        "type": "int",
        "description": "size parameter for vulners analyzer",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "vulners.Vulners",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "score_AI",
            "type": "bool",
            "description": "Score any vulnerability with Vulners AI.\r\nDefault: False",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Vulners",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": False,
        "updated_at": "2024-05-22T18:49:52.056060Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vulners.Vulners",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "skip",
            "type": "int",
            "description": "skip parameter for vulners analyzer",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Vulners",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": 0,
        "updated_at": "2024-05-23T06:45:24.105426Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "vulners.Vulners",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "size",
            "type": "int",
            "description": "size parameter for vulners analyzer",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Vulners",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": 5,
        "updated_at": "2024-05-23T06:45:24.109831Z",
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
        in [ForwardManyToOneDescriptor, ForwardOneToOneDescriptor]
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
        ("analyzers_manager", "0090_analyzer_config_cycat"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
