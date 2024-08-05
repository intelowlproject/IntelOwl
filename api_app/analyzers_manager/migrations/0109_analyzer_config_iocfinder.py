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
        "module": "iocfinder.IocFinder",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "IocFinder",
    "description": "[IocFinder](https://github.com/fhightower/ioc-finder) a library to find different types of indicators of compromise (a.k.a observables) and data pertinent to indicators of compromise!",
    "disabled": False,
    "soft_time_limit": 20,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": [],
    "supported_filetypes": ["text/plain"],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_domain_from_url",
        "type": "bool",
        "description": "to parse domain from URL",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_from_url_path",
        "type": "bool",
        "description": "parse from URL path",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_domain_from_email_address",
        "type": "bool",
        "description": "to parse domain from email address",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_address_from_cidr",
        "type": "bool",
        "description": "to parse address from CIDR",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_domain_name_from_xmpp_address",
        "type": "bool",
        "description": "to parse domain name from XMPP address",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_urls_without_scheme",
        "type": "bool",
        "description": "to parse URLs without scheme",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_imphashes",
        "type": "bool",
        "description": "to parse imphashes",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "iocfinder.IocFinder",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "parse_authentihashes",
        "type": "bool",
        "description": "to parse authentihashes",
        "is_secret": False,
        "required": False,
    },
]

values = []


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
        ("analyzers_manager", "0108_analyzer_config_iocextract"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
