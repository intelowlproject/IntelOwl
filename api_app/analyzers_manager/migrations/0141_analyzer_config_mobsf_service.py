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
        "module": "mobsf_service.MobSF_Service",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "MobSF_Service",
    "description": "[MobSF_service](https://github.com/MobSF/Mobile-Security-Framework-MobSF) can be used for a variety of use cases such as mobile application security, penetration testing, malware analysis, and privacy analysis.",
    "disabled": False,
    "soft_time_limit": 1000,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": [],
    "supported_filetypes": [
        "application/vnd.android.package-archive",
        "application/x-dex",
        "application/zip",
        "application/java-archive",
    ],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "mapping_data_model": {},
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "activity_duration",
        "type": "int",
        "description": "Time duration for mobsf to collect sufficient info in dynamic analysis before generating report. Default value is 60 seconds.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "mobsf_host",
        "type": "str",
        "description": "IP address where mobsf is hosted",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "identifier",
        "type": "str",
        "description": "Android instance identifier",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "timeout",
        "type": "int",
        "description": "Request timeout for each API call. Default value is 30 seconds",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "enable_dynamic_analysis",
        "type": "bool",
        "description": "Set to true to enable dynamic analyzer",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "default_hooks",
        "type": "str",
        "description": "Comma seperated values for default Frida scripts",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "auxiliary_hooks",
        "type": "str",
        "description": "Comma seperated values for auxiliary Frida scripts",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "frida_code",
        "type": "str",
        "description": "Frida code to load",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "mobsf_service.MobSF_Service",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "mobsf_api_key",
        "type": "str",
        "description": "MobSF API key",
        "is_secret": True,
        "required": True,
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
        ("api_app", "0065_job_mpnodesearch"),
        ("analyzers_manager", "0140_analyzerreport_analyzers_m_data_mo_a1952b_idx"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
