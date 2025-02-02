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
        "module": "nuclei.NucleiAnalyzer",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "Nuclei",
    "description": "[Nuclei](https://github.com/projectdiscovery/nuclei) is a fast, customizable vulnerability scanner that leverages YAML-based templates to detect, rank, and address security flaws. It operates using structured templates that define specific security checks.",
    "disabled": False,
    "soft_time_limit": 1200,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": True,
    "maximum_tlp": "RED",
    "observable_supported": ["ip", "url"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "mapping_data_model": {},
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "nuclei.NucleiAnalyzer",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "template_dirs",
        "type": "list",
        "description": "The template_dirs parameter allows you to specify a list of directories containing templates, each focusing on a particular category of vulnerabilities, exposures, or security assessments.\r\nAvailable Template Categories:\r\ncloud\r\ncode\r\ncves\r\nvulnerabilities\r\ndns\r\nfile\r\nheadless\r\nhelpers\r\nhttp\r\njavascript\r\nnetwork\r\npassive\r\nprofiles\r\nssl\r\nworkflows\r\nexposures",
        "is_secret": False,
        "required": False,
    }
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "nuclei.NucleiAnalyzer",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "template_dirs",
            "type": "list",
            "description": "The template_dirs parameter allows you to specify a list of directories containing templates, each focusing on a particular category of vulnerabilities, exposures, or security assessments.\r\nAvailable Template Categories:\r\ncloud\r\ncode\r\ncves\r\nvulnerabilities\r\ndns\r\nfile\r\nheadless\r\nhelpers\r\nhttp\r\njavascript\r\nnetwork\r\npassive\r\nprofiles\r\nssl\r\nworkflows\r\nexposures",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "Nuclei",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": [],
        "updated_at": "2025-01-08T08:33:45.653741Z",
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
        (
            "analyzers_manager",
            "0147_alter_analyzer_config_feodo_yaraify_urlhaus_yaraify_scan",
        ),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
