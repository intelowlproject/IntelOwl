from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "Yara",
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": {
            "minute": "0",
            "hour": "0",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "update_task": {
            "crontab": {
                "minute": "0",
                "hour": "0",
                "day_of_week": "*",
                "day_of_month": "*",
                "month_of_year": "*",
            },
            "name": "api_app.analyzers_manager.file_analyzers.yara_scan.YaraScanUpdate",
            "task": "intel_owl.tasks.update",
            "kwargs": '{"python_module_pk": 122}',
            "queue": "local",
            "enabled": True,
        },
        "module": "yara_scan.YaraScan",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "description": "scan a file with Yara rules",
    "disabled": False,
    "soft_time_limit": 120,
    "routing_key": "local",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": [],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": ["application/vnd.tcpdump.pcap"],
    "health_check_task": None,
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "yara_scan.YaraScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "ignore",
        "type": "list",
        "description": "ignore these rules",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yara_scan.YaraScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "local_rules",
        "type": "bool",
        "description": "If True, use local rules present at /opt/deploy/files_required/yara/YOUR_USER/custom_rule",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yara_scan.YaraScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "repositories",
        "type": "list",
        "description": "Repositories that will be constantly updated",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "yara_scan.YaraScan",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "private_repositories",
        "type": "dict",
        "description": 'Private repositories in the following format: {"username@provider:org/repository.git":"ssh key"}. Use double quote, don\'t worry about whitespace.',
        "is_secret": True,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "yara_scan.YaraScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "ignore",
            "type": "list",
            "description": "ignore these rules",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": [
            "generic_anomalies.yar",
            "general_cloaking.yar",
            "thor_inverse_matches.yar",
            "yara_mixed_ext_vars.yar",
            "thor-webshells.yar",
        ],
        "updated_at": "2024-02-09T10:52:20.577189Z",
        "owner": None,
        "analyzer_config": "Yara",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yara_scan.YaraScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "local_rules",
            "type": "bool",
            "description": "If True, use local rules present at /opt/deploy/files_required/yara/YOUR_USER/custom_rule",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": False,
        "updated_at": "2024-02-09T10:52:20.589012Z",
        "owner": None,
        "analyzer_config": "Yara",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "yara_scan.YaraScan",
                "base_path": "api_app.analyzers_manager.file_analyzers",
            },
            "name": "repositories",
            "type": "list",
            "description": "Repositories that will be constantly updated",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": [
            "https://github.com/dr4k0nia/yara-rules",
            "https://github.com/elastic/protections-artifacts",
            "https://github.com/embee-research/Yara",
            "https://github.com/elceef/yara-rulz",
            "https://github.com/JPCERTCC/jpcert-yara",
            "https://github.com/SIFalcon/Detection/",
            "https://github.com/bartblaze/Yara-rules",
            "https://github.com/intezer/yara-rules",
            "https://github.com/advanced-threat-research/Yara-Rules",
            "https://github.com/stratosphereips/yara-rules",
            "https://github.com/reversinglabs/reversinglabs-yara-rules",
            "https://github.com/sbousseaden/YaraHunts",
            "https://github.com/InQuest/yara-rules",
            "https://github.com/StrangerealIntel/DailyIOC",
            "https://github.com/mandiant/red_team_tool_countermeasures",
            "https://github.com/fboldewin/YARA-rules",
            "https://github.com/Yara-Rules/rules.git",
            "https://github.com/Neo23x0/signature-base.git",
            "https://yaraify-api.abuse.ch/yarahub/yaraify-rules.zip",
        ],
        "updated_at": "2024-02-09T10:52:28.002269Z",
        "owner": None,
        "analyzer_config": "Yara",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
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
        ("analyzers_manager", "0002_0144_analyzer_config_yeti"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
