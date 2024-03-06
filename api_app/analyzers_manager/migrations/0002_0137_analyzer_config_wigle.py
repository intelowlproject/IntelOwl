from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "WiGLE",
    "python_module": {
        "module": "wigle.WiGLE",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Maps and database of 802.11 wireless networks, with statistics, submitted by wardrivers, netstumblers, and net huggers. Also, the string to be passed in input field of generic analyzers have a format. Different variables are separated by semicolons(`;`) and the field-name and value are separated by equals sign(`=`). Example string for search_type `CDMA Network` is `sid=12345;nid=12345;bsid=12345`.",
    "disabled": False,
    "soft_time_limit": 30,
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
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "wigle.WiGLE",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "search_type",
        "type": "str",
        "description": "Corresponds to different routes mentioned in [docs](https://api.wigle.net/swagger#/v3_ALPHA). (options: `WiFi Network`, `CDMA Network`, `Bluetooth Network`, `GSM/LTE/WCDMA Network`).",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "wigle.WiGLE",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "wigle.WiGLE",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "search_type",
            "type": "str",
            "description": "Corresponds to different routes mentioned in [docs](https://api.wigle.net/swagger#/v3_ALPHA). (options: `WiFi Network`, `CDMA Network`, `Bluetooth Network`, `GSM/LTE/WCDMA Network`).",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "WiFi Network",
        "updated_at": "2024-02-09T10:52:20.547236Z",
        "owner": None,
        "analyzer_config": "WiGLE",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
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
        ("analyzers_manager", "0002_0136_analyzer_config_whoisxmlapi"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
