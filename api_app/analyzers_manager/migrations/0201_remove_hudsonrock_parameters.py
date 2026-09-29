# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.db import migrations

PARAMETER_NAMES = [
    "api_key_name",
    "compromised_since",
    "compromised_until",
    "page",
    "added_since",
    "added_until",
    "installed_software",
    "sort_by",
    "domain_cred_type",
    "domain_filtered",
    "third_party_domains",
]

# Field values copied from 0089_analyzer_config_hudsonrock.py.
PARAMETERS = [
    {
        "name": "compromised_since",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "name": "compromised_until",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "name": "page",
        "type": "int",
        "description": (
            "The API utilises data pagination, where a maximum of 50 documents (stealers) per request "
            "are returned. When querying for a specific page, such as page 2, the API will skip the "
            "first 50 documents and return the next 50.\r\ndefault : 1"
        ),
        "is_secret": False,
        "required": False,
    },
    {
        "name": "added_since",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "name": "api_key_name",
        "type": "str",
        "description": "",
        "is_secret": True,
        "required": True,
    },
    {
        "name": "added_until",
        "type": "str",
        "description": "ISO Date: YYYY-MM-DDThh:mm:ss.sssZ\r\ne.g: 2024-05-17T11:22:59.180Z\r\ndefault: All Time",
        "is_secret": False,
        "required": False,
    },
    {
        "name": "installed_software",
        "type": "bool",
        "description": "When set to true, installed software from the compromised computer will be shown.",
        "is_secret": False,
        "required": False,
    },
    {
        "name": "sort_by",
        "type": "str",
        "description": (
            "Options/Data Type: \r\n1.date_compromised\r\n2.date_uploaded\r\nDefault: date_compromised\r\n"
            "The API allows for sorting of the machine records by date of compromise or date added to "
            "Hudson Rock's system, with the results being returned in descending order."
        ),
        "is_secret": False,
        "required": False,
    },
    {
        "name": "domain_cred_type",
        "type": "str",
        "description": (
            "Options/Data Type: \r\n1.employees\r\n2.users\r\n3. all(default)\r\n"
            "Cavalier supports two type of credentials: Employees and users (APKs are considered as "
            "‘user’ type). Filtering displays only one type for the desired domain"
        ),
        "is_secret": False,
        "required": False,
    },
    {
        "name": "domain_filtered",
        "type": "bool",
        "description": (
            "Filter results to show only credentials which are related to the specified domain/s.\r\n"
            '*This is only applicable for when "type" parameter is set to "employees".'
        ),
        "is_secret": False,
        "required": False,
    },
    {
        "name": "third_party_domains",
        "type": "bool",
        "description": (
            "When set to true, corporate credentials of compromised employees of the searched domain "
            "found in external domains will be shown, i.e - in a search for company.com "
            "john@company.com logging into zoom.us will be shown.\r\n"
            '*This is only applicable for when "type" parameter is set to "employees".'
        ),
        "is_secret": False,
        "required": False,
    },
]


def _python_module(apps):
    PythonModule = apps.get_model("api_app", "PythonModule")
    return PythonModule.objects.get(
        module="hudsonrock.HudsonRock",
        base_path="api_app.analyzers_manager.observable_analyzers",
    )


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    pm = _python_module(apps)
    for name in PARAMETER_NAMES:
        Parameter.objects.get(name=name, python_module=pm).delete()


def reverse_migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    pm = _python_module(apps)
    for param in PARAMETERS:
        Parameter.objects.create(python_module=pm, **param)


class Migration(migrations.Migration):
    dependencies = [
        ("analyzers_manager", "0200_analyzer_config_presend_addressrisk"),
    ]

    operations = [
        migrations.RunPython(migrate, reverse_migrate),
    ]
