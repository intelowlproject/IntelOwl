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
            "hour": "0",
            "day_of_week": "*",
            "day_of_month": "*",
            "month_of_year": "*",
        },
        "update_schedule": None,
        "module": "hudsonrock.HudsonRock",
        "base_path": "api_app.analyzers_manager.observable_analyzers",
    },
    "name": "HudsonRock",
    "description": "[Hudson Rock](https://cavalier.hudsonrock.com/docs) provides its clients the ability to query a database of over 27,541,128 computers which were compromised through global info-stealer campaigns performed by threat actors. The database is updated with new compromised computers every day, offering cybersecurity providers the ability to alert security teams ahead of imminent attacks, when users get compromised and have their credentials stolen.",
    "disabled": False,
    "soft_time_limit": 60,
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
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "compromised_since",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "compromised_until",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "page",
        "type": "int",
        "description": "The API utilises data pagination, where a maximum of 50 documents (stealers) per request are returned. When querying for a specific page, such as page 2, the API will skip the first 50 documents and return the next 50.\r\ndefault : 1",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "added_since",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "added_until",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "installed_software",
        "type": "bool",
        "description": "When set to true, installed software from the compromised computer will be shown.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "sort_by",
        "type": "str",
        "description": "Options/Data Type: \r\n1.date_compromised\r\n2.date_uploaded\r\nDefault: date_compromised\r\nThe API allows for sorting of the machine records by date of compromise or date added to Hudson Rock's system, with the results being returned in descending order.",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "domain_cred_type",
        "type": "str",
        "description": "Options/Data Type: \r\n1.employees\r\n2.users\r\n3. all(default)\r\nCavalier supports two type of credentials: Employees and users (APKs are considered as ‘user’ type). Filtering displays only one type for the desired domain",
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "domain_filtered",
        "type": "bool",
        "description": 'Filter results to show only credentials which are related to the specified domain/s.\r\n*This is only applicable for when "type" parameter is set to "employees".',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "hudsonrock.HudsonRock",
            "base_path": "api_app.analyzers_manager.observable_analyzers",
        },
        "name": "third_party_domains",
        "type": "bool",
        "description": 'When set to true, corporate credentials of compromised employees of the searched domain found in external domains will be shown, i.e - in a search for company.com john@company.com logging into zoom.us will be shown.\r\n*This is only applicable for when "type" parameter is set to "employees".',
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
        ("analyzers_manager", "0088_phoneinfoga_parameters"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
