from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "bbot.Bbot",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "Bbot",
    "description": "BBOT is a multipurpose scanner inspired by Spiderfoot, built to automate your Recon, Bug Bounties, and ASM!",
    "disabled": False,
    "soft_time_limit": 120,
    "routing_key": "default",
    "health_check_status": False,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": ["url", "domain"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",

}

params = [
    {
        "python_module": {
            "module": "bbot.Bbot",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "preset",
        "type": "str",
        "description": "preset for BBOT",
        "is_secret": False,
        "required": False,
    }
]
values = [
    {
        "parameter": {
            "python_module": {
                "module": "bbot.Bbot",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "preset",
            "type": "str",
            "description": "preset for BBOT",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "web-basic",
        "updated_at": "2025-02-17T15:15:57.247Z",
        "analyzer_config":  "Bbot",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "owner": None,
    }
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
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0143_alter_analyzer_config_phishing_extractor_and_form_compiler"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False

