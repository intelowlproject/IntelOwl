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
        "module": "criminalip.criminalip_scan.CriminalIpScan",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "CriminalIpScan",
    "description": "[Criminal IP](https://www.criminalip.io/) is an OSINT search engine specialized in attack surface assessment and threat hunting. It offers extensive cyber threat intelligence, including device reputation, geolocation, IP reputation for C2 or scanners, domain safety, malicious link detection, and APT attack vectors via search and API.",
    "disabled": False,
    "soft_time_limit": 10,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["ip", "domain", "generic"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key",
        "type": "str",
        "description": "api key for criminal ip",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "malicious_info",
        "type": "bool",
        "description": "for IP, default endpoint",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "privacy_threat",
        "type": "bool",
        "description": "for IP, privacy-threat endpoint",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "is_safe_dns_server",
        "type": "bool",
        "description": "for IP, is-safe-dns-server endpoint",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "suspicious_info",
        "type": "bool",
        "description": "for IP, suspicious_info endpoint",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "banner_search",
        "type": "bool",
        "description": "for generics",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "criminalip.criminalip_scan.CriminalIpScan",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "banner_stats",
        "type": "bool",
        "description": "for generics",
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

    PythonModule = apps.get_model("api_app", "PythonModule")
    # we will update the python module path
    pm = PythonModule.objects.get(
        module="criminalip.CriminalIp",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm.module = "criminalip.criminalip.CriminalIp"
    pm.save()
    Model.objects.filter(name="CriminalIp").update(python_module=pm)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()
    PythonModule = apps.get_model("api_app", "PythonModule")
    pm = PythonModule.objects.get(
        module="criminalip.criminalip.CriminalIp",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )
    pm.module = "criminalip.CriminalIp"
    pm.save()
    Model.objects.filter(name="CriminalIp").update(python_module=pm)


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0062_alter_parameter_python_module"),
        ("analyzers_manager", "0111_analyzer_config_criminalip"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
