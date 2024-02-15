from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "name": "DNStwist",
    "python_module": {
        "module": "dnstwist.DNStwist",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "scans for potentially malicious permutations of a domain name",
    "disabled": False,
    "soft_time_limit": 300,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "AMBER",
    "observable_supported": ["domain", "url"],
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
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "mxcheck",
        "type": "bool",
        "description": "Find suspicious mail servers and flag them with SPYING-MX string.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "tld_dict",
        "type": "str",
        "description": "Dictionary to use with `tld` argument. Options: `common_tlds.dict/abused_tlds.dict`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "fuzzy_hash",
        "type": "str",
        "description": "Fuzzy Hash to use to detect similarities. Options `ssdeep/tlsh`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "user_agent",
        "type": "str",
        "description": "User Agent used to connect to sites",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "nameservers",
        "type": "str",
        "description": "Alternative DNS servers to use. Add them separated by commas",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "language_dict",
        "type": "str",
        "description": "Dictionary to use with `dictionary` argument. Options: `english.dict/french.dict/polish.dict`",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "dnstwist.DNStwist",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "fuzzy_hash_url",
        "type": "str",
        "description": "Override URL to fetch the original web page from",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "mxcheck",
            "type": "bool",
            "description": "Find suspicious mail servers and flag them with SPYING-MX string.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": True,
        "updated_at": "2024-02-09T10:52:16.327136Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "tld_dict",
            "type": "str",
            "description": "Dictionary to use with `tld` argument. Options: `common_tlds.dict/abused_tlds.dict`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:16.339816Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "fuzzy_hash",
            "type": "str",
            "description": "Fuzzy Hash to use to detect similarities. Options `ssdeep/tlsh`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "ssdeep",
        "updated_at": "2024-02-09T10:52:16.352844Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "user_agent",
            "type": "str",
            "description": "User Agent used to connect to sites",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.34",
        "updated_at": "2024-02-09T10:52:16.365784Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "nameservers",
            "type": "str",
            "description": "Alternative DNS servers to use. Add them separated by commas",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:16.379533Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "language_dict",
            "type": "str",
            "description": "Dictionary to use with `dictionary` argument. Options: `english.dict/french.dict/polish.dict`",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:16.391896Z",
        "owner": None,
        "analyzer_config": "DNStwist",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "dnstwist.DNStwist",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "fuzzy_hash_url",
            "type": "str",
            "description": "Override URL to fetch the original web page from",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "",
        "updated_at": "2024-02-09T10:52:16.404265Z",
        "owner": None,
        "analyzer_config": "DNStwist",
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
        ("analyzers_manager", "0002_0030_analyzer_config_dnsdb"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
