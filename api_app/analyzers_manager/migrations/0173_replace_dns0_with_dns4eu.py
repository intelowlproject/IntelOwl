# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

# New Plugins definition
dns4eu_resolver = {
    "name": "DNS4EU",
    "python_module": {
        "module": "dns.dns_resolvers.dns4eu_resolver.DNS4EUResolver",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Retrieve current domain resolution with [DNS4EU](https://www.joindns4.eu/) DoH (DNS over HTTPS)",
    "disabled": False,
    "soft_time_limit": 30,
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

dns4eu_malicious_detector = {
    "name": "DNS4EU_Malicious_Detector",
    "python_module": {
        "module": "dns.dns_malicious_detectors.dns4eu_malicious_detector.DNS4EUMaliciousDetector",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "description": "Check if a domain or an url is marked as malicious in [DNS4EU](https://www.joindns4.eu/) database",
    "disabled": False,
    "soft_time_limit": 30,
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

# Parameters for DNS4EU Resolver (same as DNS0)
resolver_params = [
    {
        "python_module": {
            "module": "dns.dns_resolvers.dns4eu_resolver.DNS4EUResolver",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "query_type",
        "type": "str",
        "description": "Query type against the chosen DNS resolver. Default is A.",
        "is_secret": False,
        "required": False,
    }
]

resolver_values = [
    {
        "parameter": {
            "python_module": {
                "module": "dns.dns_resolvers.dns4eu_resolver.DNS4EUResolver",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "query_type",
            "type": "str",
            "description": "Query type against the chosen DNS resolver. Default is A.",
            "is_secret": False,
            "required": False,
        },
        "for_organization": False,
        "value": "A",
        "owner": None,
        "analyzer_config": "DNS4EU",
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
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        else:
            try:
                value = other_model.objects.get(pk=value)
            except (ValueError, other_model.DoesNotExist):
                # Fallback to name lookup if PK lookup fails (e.g. string passed for ID)
                value = other_model.objects.get(name=value)
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
        print(f"DEBUG: Found exact match for {Model.__name__}")
    except Model.DoesNotExist:
        print(f"DEBUG: No exact match for {Model.__name__} data={no_mtm}")
        if Model.__name__ == "AnalyzerConfig":
            try:
                o = Model.objects.get(name=no_mtm.get("name"))
                print(f"DEBUG: Found by name {no_mtm.get('name')}, updating...")
                for k, v in no_mtm.items():
                    setattr(o, k, v)
                o.full_clean()
                o.save()
            except Model.DoesNotExist:
                print(f"DEBUG: creating new {Model.__name__}")
                o = Model(**no_mtm)
                o.full_clean()
                o.save()
        elif Model.__name__ == "Parameter":
            try:
                # Parameter uniqueness is likely name + python_module
                o = Model.objects.get(
                    name=no_mtm.get("name"), python_module=no_mtm.get("python_module")
                )
                print("DEBUG: Found Parameter by name+module, updating...")
                for k, v in no_mtm.items():
                    setattr(o, k, v)
                o.full_clean()
                o.save()
            except Model.DoesNotExist:
                print(f"DEBUG: creating new {Model.__name__}")
                o = Model(**no_mtm)
                o.full_clean()
                o.save()
        else:
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
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # 1. Remove Old Plugins
    old_plugins = ["DNS0_EU", "DNS0_EU_Malicious_Detector"]
    AnalyzerConfig.objects.filter(name__in=old_plugins).delete()

    # 2. Add New DNS4EU Resolver
    python_path = dns4eu_resolver.pop("model")
    Model = apps.get_model(*python_path.split("."))
    _create_object(Model, dns4eu_resolver)
    for param in resolver_params:
        _create_object(Parameter, param)
    for value in resolver_values:
        _create_object(PluginConfig, value)

    # 3. Add New DNS4EU Malicious Detector
    python_path = dns4eu_malicious_detector.pop("model")
    Model = apps.get_model(*python_path.split("."))
    _create_object(Model, dns4eu_malicious_detector)


def reverse_migrate(apps, schema_editor):
    AnalyzerConfig = apps.get_model("analyzers_manager", "AnalyzerConfig")

    # Remove New Plugins
    new_plugins = ["DNS4EU", "DNS4EU_Malicious_Detector"]
    AnalyzerConfig.objects.filter(name__in=new_plugins).delete()

    # (Optional) We could re-add the old plugins here if we wanted full reversibility
    # but the files are gone, so it might fail if we try to instantiate them incorrectly or if we rely on the old file paths
    # For now, we just remove the new ones.


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0172_analyzer_config_hibppasswords"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
    atomic = False
