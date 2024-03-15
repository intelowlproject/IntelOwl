from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": {
            "minute": "0",
            "hour": "*",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "update_schedule": None,
        "module": "bgp_ranking.BGPRanking",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "BGP_Ranking",
    "description": "[BGP Ranking](https://github.com/D4-project/BGP-Ranking) provides a way to collect such malicious activities, aggregate the information per ASN and provide a ranking model to rank the ASN from the most malicious to the less malicious ASN.",
    "disabled": False,
    "soft_time_limit": 60,
    "routing_key": "default",
    "health_check_status": True,
    "type": "observable",
    "docker_based": False,
    "maximum_tlp": "CLEAR",
    "observable_supported": ["ip"],
    "supported_filetypes": [],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "bgp_ranking.BGPRanking",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "period",
        "type": "int",
        "description": "period for bgp-ranking in days",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "bgp_ranking.BGPRanking",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "timeout",
        "type": "int",
        "description": "timeout for bgp-ranking in seconds",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "bgp_ranking.BGPRanking",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "url",
        "type": "str",
        "description": "url for bgp-ranking default is https://bgpranking-ng.circl.lu",
        "is_secret": False,
        "required": False,
    },
]

values = [
    {
        "parameter": {
            "python_module": {
                "module": "bgp_ranking.BGPRanking",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "period",
            "type": "int",
            "description": "period for bgp-ranking in days",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "BGP_Ranking",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": 0,
        "updated_at": "2024-03-13T16:00:13.078391Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "bgp_ranking.BGPRanking",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "timeout",
            "type": "int",
            "description": "timeout for bgp-ranking in seconds",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "BGP_Ranking",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": 5,
        "updated_at": "2024-03-13T16:00:35.931795Z",
        "owner": None,
    },
    {
        "parameter": {
            "python_module": {
                "module": "bgp_ranking.BGPRanking",
                "base_path": "api_app.analyzers_manager.observable_analyzers",
            },
            "name": "url",
            "type": "str",
            "description": "url for bgp-ranking default is https://bgpranking-ng.circl.lu",
            "is_secret": False,
            "required": False,
        },
        "analyzer_config": "BGP_Ranking",
        "connector_config": None,
        "visualizer_config": None,
        "ingestor_config": None,
        "pivot_config": None,
        "for_organization": False,
        "value": "https://bgpranking-ng.circl.lu",
        "updated_at": "2024-03-13T16:35:34.870882Z",
        "owner": None,
    },
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
        ("api_app", "0061_job_depth_analysis"),
        ("analyzers_manager", "0068_analyzer_config_feodo_tracker"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
