from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Netlas",
    "config": {"queue": "default", "soft_time_limit": 60},
    "update_schedule": None,
    "update_task": None,
    "description": "[Netlas API](https://netlas.io/api) provides accurate technical information on IP addresses.",
    "disabled": False,
    "python_module": "netlas.Netlas",
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "disabled_in_organizations": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "id": 464,
        "name": "api_key_name",
        "type": "str",
        "description": "API key for the netlas analyzer",
        "is_secret": True,
        "required": True,
        "analyzer_config": "Netlas",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
    }
]

values = []


def _get_real_obj(Model, field, value):
    if (
        type(getattr(Model, field))
        in [
            ForwardManyToOneDescriptor,
            ForwardOneToOneDescriptor,
        ]
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
        ("analyzers_manager", "0034_periodic_tasks"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
